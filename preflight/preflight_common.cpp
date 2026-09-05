#define WIN32_LEAN_AND_MEAN
#include "preflight.h"

#include <windows.h>

#include <intrin.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "knhv_control_ioctl.h"

namespace knhv_preflight {
namespace {

namespace fs = std::filesystem;

constexpr DWORD kAcpiProvider = 0x41435049U;
constexpr DWORD kDmarTable = 0x52414D44U;
constexpr int kWhvCapabilityHypervisorPresent = 0;
constexpr int kExitSuccess = 0;
constexpr int kExitBlocked = 10;
constexpr int kExitInvalid = 11;

enum class TriState {
    Unknown,
    No,
    Yes,
};

const char* TriStateText(TriState state) {
    switch (state) {
        case TriState::Yes:
            return "yes";
        case TriState::No:
            return "no";
        default:
            return "unknown";
    }
}

const char* GateStateText(GateState state) {
    switch (state) {
        case GateState::Pass:
            return "pass";
        case GateState::Fail:
            return "fail";
        default:
            return "unknown";
    }
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
            case '\\':
                output << "\\\\";
                break;
            case '"':
                output << "\\\"";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (character < 0x20U) {
                    output << "\\u" << std::hex << std::setw(4)
                           << std::setfill('0')
                           << static_cast<unsigned>(character);
                } else {
                    output << static_cast<char>(character);
                }
                break;
        }
    }
    return output.str();
}

std::string Narrow(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                            static_cast<int>(value.size()), result.data(),
                            required, nullptr, nullptr) != required) {
        return {};
    }
    return result;
}

std::string NowIso8601() {
    SYSTEMTIME local_time{};
    GetLocalTime(&local_time);
    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << local_time.wYear << '-'
           << std::setw(2) << local_time.wMonth << '-'
           << std::setw(2) << local_time.wDay << 'T' << std::setw(2)
           << local_time.wHour << ':' << std::setw(2) << local_time.wMinute
           << ':' << std::setw(2) << local_time.wSecond << '.' << std::setw(3)
           << local_time.wMilliseconds << " local";
    return output.str();
}

struct CpuSnapshot {
    std::string vendor;
    std::string brand;
    std::string hypervisor_vendor;
    std::uint32_t max_basic_leaf = 0U;
    std::uint32_t max_extended_leaf = 0U;
    bool vmx = false;
    bool hypervisor_bit = false;
    bool invariant_tsc = false;
};

struct TopologySnapshot {
    std::uint32_t processor_groups = 0U;
    std::uint32_t logical_processors = 0U;
    std::uint32_t physical_cores = 0U;
    bool complete = false;
};

struct RegistryDword {
    TriState state = TriState::Unknown;
    DWORD value = 0U;
    LONG error = ERROR_SUCCESS;
};

struct ServiceSnapshot {
    TriState present = TriState::Unknown;
    TriState running = TriState::Unknown;
};

struct PlatformSnapshot {
    TriState secure_boot = TriState::Unknown;
    TriState vbs_configured = TriState::Unknown;
    TriState hvci_configured = TriState::Unknown;
    TriState dmar_table = TriState::Unknown;
    TriState whp_library = TriState::Unknown;
    TriState whp_api = TriState::Unknown;
    TriState whp_hypervisor = TriState::Unknown;
    TriState uefi = TriState::Unknown;
    TriState vmx_firmware = TriState::Unknown;
    std::string os_version = "unknown";
    std::string firmware_type = "unknown";
    std::array<std::pair<std::string, ServiceSnapshot>, 3> services = {{
        {"vmms", {}}, {"HvHost", {}}, {"vmcompute", {}}}};
};

struct ProviderSnapshot {
    TriState device = TriState::Unknown;
    TriState unique_owner = TriState::Unknown;
    TriState knhv_boot_l0 = TriState::Unknown;
    TriState nested_vmx = TriState::Unknown;
    std::string reason = "not queried";
    std::uint32_t status = 0U;
    std::uint32_t flags = 0U;
    std::uint64_t features = 0U;
};

struct HostSnapshot {
    CpuSnapshot cpu;
    TopologySnapshot topology;
    PlatformSnapshot platform;
    ProviderSnapshot provider;
};

void ReadCpuid(int leaf, int subleaf, std::array<int, 4>& registers) {
    __cpuidex(registers.data(), leaf, subleaf);
}

std::string FourRegisterText(const std::array<int, 4>& registers,
                             std::initializer_list<int> order) {
    std::string value;
    value.reserve(order.size() * sizeof(int));
    for (const int index : order) {
        const int register_value = registers[static_cast<std::size_t>(index)];
        for (std::size_t byte = 0; byte < sizeof(register_value); ++byte) {
            value.push_back(static_cast<char>((register_value >> (byte * 8U)) &
                                              0xFF));
        }
    }
    return value;
}

CpuSnapshot CollectCpu() {
    CpuSnapshot snapshot;
    std::array<int, 4> registers{};
    ReadCpuid(0, 0, registers);
    snapshot.max_basic_leaf = static_cast<std::uint32_t>(registers[0]);
    snapshot.vendor = FourRegisterText(registers, {1, 3, 2});
    if (snapshot.max_basic_leaf >= 1U) {
        ReadCpuid(1, 0, registers);
        snapshot.vmx = (registers[2] & (1 << 5)) != 0;
        snapshot.hypervisor_bit = (registers[2] & (1 << 31)) != 0;
    }
    ReadCpuid(0x80000000, 0, registers);
    snapshot.max_extended_leaf = static_cast<std::uint32_t>(registers[0]);
    if (snapshot.max_extended_leaf >= 0x80000002U) {
        std::array<int, 12> brand_registers{};
        for (int leaf = 0; leaf < 3; ++leaf) {
            ReadCpuid(0x80000002 + leaf, 0, registers);
            std::copy(registers.begin(), registers.end(),
                      brand_registers.begin() + leaf * 4);
        }
        snapshot.brand.assign(reinterpret_cast<const char*>(brand_registers.data()),
                              sizeof(brand_registers));
        while (!snapshot.brand.empty() && snapshot.brand.back() == ' ') {
            snapshot.brand.pop_back();
        }
        snapshot.brand.erase(
            std::find(snapshot.brand.begin(), snapshot.brand.end(), '\0'),
            snapshot.brand.end());
    }
    if (snapshot.max_extended_leaf >= 0x80000007U) {
        ReadCpuid(0x80000007, 0, registers);
        snapshot.invariant_tsc = (registers[3] & (1 << 8)) != 0;
    }
    if (snapshot.hypervisor_bit) {
        ReadCpuid(0x40000000, 0, registers);
        const std::uint32_t max_hypervisor_leaf =
            static_cast<std::uint32_t>(registers[0]);
        if (max_hypervisor_leaf >= 0x40000000U) {
            snapshot.hypervisor_vendor = FourRegisterText(registers, {1, 2, 3});
        }
    }
    return snapshot;
}

TopologySnapshot CollectTopology() {
    TopologySnapshot snapshot;
    snapshot.processor_groups = GetActiveProcessorGroupCount();
    snapshot.logical_processors =
        GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);

    DWORD required = 0U;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr,
                                     &required);
    if (required == 0U) return snapshot;
    std::vector<std::uint8_t> buffer(required);
    if (!GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                buffer.data()),
            &required)) {
        return snapshot;
    }

    constexpr DWORD kRecordHeaderSize = sizeof(DWORD) * 2U;
    DWORD offset = 0U;
    while (offset + kRecordHeaderSize <= required) {
        const auto* entry = reinterpret_cast<
            const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() +
                                                              offset);
        if (entry->Size < kRecordHeaderSize ||
            offset + entry->Size > required) {
            return snapshot;
        }
        if (entry->Relationship == RelationProcessorCore) {
            ++snapshot.physical_cores;
        }
        offset += entry->Size;
    }
    snapshot.complete = offset == required && snapshot.physical_cores != 0U &&
                        snapshot.logical_processors != 0U;
    return snapshot;
}

RegistryDword ReadRegistryDword(const wchar_t* path, const wchar_t* value) {
    RegistryDword result;
    DWORD data = 0U;
    DWORD data_size = sizeof(data);
    const LONG error = RegGetValueW(
        HKEY_LOCAL_MACHINE, path, value, RRF_RT_REG_DWORD, nullptr, &data,
        &data_size);
    result.error = error;
    if (error != ERROR_SUCCESS || data_size != sizeof(data)) return result;
    result.value = data;
    result.state = data == 0U ? TriState::No : TriState::Yes;
    return result;
}

ServiceSnapshot QueryService(const wchar_t* name) {
    ServiceSnapshot snapshot;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) return snapshot;
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        const DWORD error = GetLastError();
        snapshot.present = error == ERROR_SERVICE_DOES_NOT_EXIST
                               ? TriState::No
                               : TriState::Unknown;
        CloseServiceHandle(manager);
        return snapshot;
    }
    snapshot.present = TriState::Yes;
    SERVICE_STATUS_PROCESS status{};
    DWORD returned = 0U;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&status),
                             sizeof(status), &returned)) {
        snapshot.running = status.dwCurrentState == SERVICE_RUNNING
                               ? TriState::Yes
                               : TriState::No;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return snapshot;
}

TriState QuerySecureBoot() {
    const RegistryDword value = ReadRegistryDword(
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        L"UEFISecureBootEnabled");
    return value.state;
}

TriState QueryDmar() {
    SetLastError(ERROR_SUCCESS);
    const UINT size = EnumSystemFirmwareTables(kAcpiProvider, nullptr, 0U);
    if (size == 0U) {
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_NOT_FOUND
                   ? TriState::No
                   : TriState::Unknown;
    }
    std::vector<DWORD> table_ids((size + sizeof(DWORD) - 1U) /
                                 sizeof(DWORD));
    if (EnumSystemFirmwareTables(kAcpiProvider, table_ids.data(), size) ==
        0U) {
        return TriState::Unknown;
    }
    return std::find(table_ids.begin(), table_ids.end(), kDmarTable) ==
                   table_ids.end()
               ? TriState::No
               : TriState::Yes;
}

TriState QueryFirmwareType(std::string& text) {
    FIRMWARE_TYPE type = FirmwareTypeUnknown;
    if (!GetFirmwareType(&type)) return TriState::Unknown;
    switch (type) {
        case FirmwareTypeUefi:
            text = "UEFI";
            return TriState::Yes;
        case FirmwareTypeBios:
            text = "BIOS";
            return TriState::No;
        default:
            text = "unknown";
            return TriState::Unknown;
    }
}

TriState QueryOsVersion(std::string& text) {
    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) return TriState::Unknown;
    const auto query = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (query == nullptr) return TriState::Unknown;
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (query(&version) != ERROR_SUCCESS) return TriState::Unknown;
    std::ostringstream output;
    output << version.dwMajorVersion << '.' << version.dwMinorVersion << '.'
           << version.dwBuildNumber;
    text = output.str();
    return TriState::Yes;
}

void QueryWhp(PlatformSnapshot& snapshot) {
    HMODULE library = LoadLibraryW(L"WinHvPlatform.dll");
    if (library == nullptr) {
        snapshot.whp_library = TriState::No;
        return;
    }
    snapshot.whp_library = TriState::Yes;
    using WhvGetCapabilityFn = HRESULT(WINAPI*)(int, void*, UINT32, UINT32*);
    const auto query = reinterpret_cast<WhvGetCapabilityFn>(
        GetProcAddress(library, "WHvGetCapability"));
    if (query == nullptr) {
        FreeLibrary(library);
        return;
    }
    snapshot.whp_api = TriState::Yes;
    BOOL present = FALSE;
    UINT32 written = 0U;
    const HRESULT result = query(kWhvCapabilityHypervisorPresent, &present,
                                 sizeof(present), &written);
    if (SUCCEEDED(result) && written >= sizeof(present)) {
        snapshot.whp_hypervisor = present != FALSE ? TriState::Yes
                                                   : TriState::No;
    }
    FreeLibrary(library);
}

void QueryProvider(ProviderSnapshot& snapshot) {
    HANDLE device = CreateFileW(L"\\\\.\\KNHVControl", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        snapshot.device = TriState::No;
        std::ostringstream reason;
        reason << "KNHVControl unavailable win32=" << GetLastError();
        snapshot.reason = reason.str();
        return;
    }
    snapshot.device = TriState::Yes;
    knhv::HvQueryCapsIn request{};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = 0x5052464C49474854ULL;
    knhv::HvQueryCapsOut response{};
    DWORD returned = 0U;
    const BOOL ok = DeviceIoControl(
        device, IOCTL_KNHV_QUERY_CAPS, &request, sizeof(request), &response,
        sizeof(response), &returned, nullptr);
    if (ok == FALSE || returned != sizeof(response) ||
        response.version != knhv::kAbiVersion ||
        response.size != sizeof(response)) {
        const DWORD error = GetLastError();
        std::ostringstream reason;
        reason << "capability query failed win32=" << error;
        snapshot.reason = reason.str();
        CloseHandle(device);
        return;
    }
    snapshot.status = static_cast<std::uint32_t>(response.status);
    snapshot.flags = response.snapshot.status_flags;
    snapshot.features = response.snapshot.feature_bits;
    snapshot.reason = "capability snapshot received";
    const bool boot_l0 =
        (snapshot.flags & knhv::kFlagKnhvBootL0Active) != 0U;
    const bool outer_l0 = (snapshot.flags & knhv::kFlagOuterL0Active) != 0U;
    const bool nested =
        (snapshot.flags & knhv::kFlagNestedVmx) != 0U &&
        (snapshot.features & knhv::kCapNestedVmx) != 0U;
    snapshot.knhv_boot_l0 = boot_l0 ? TriState::Yes : TriState::No;
    snapshot.nested_vmx = nested ? TriState::Yes : TriState::No;
    snapshot.unique_owner = (boot_l0 == outer_l0)
                                ? TriState::Unknown
                                : TriState::Yes;
    if (outer_l0) snapshot.unique_owner = TriState::No;
    CloseHandle(device);
}

HostSnapshot CollectHost() {
    HostSnapshot snapshot;
    snapshot.cpu = CollectCpu();
    snapshot.topology = CollectTopology();
    snapshot.platform.secure_boot = QuerySecureBoot();
    snapshot.platform.vmx_firmware = TriState::Unknown;
    snapshot.platform.dmar_table = QueryDmar();
    snapshot.platform.uefi = QueryFirmwareType(snapshot.platform.firmware_type);
    QueryOsVersion(snapshot.platform.os_version);
    const RegistryDword vbs = ReadRegistryDword(
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        L"EnableVirtualizationBasedSecurity");
    snapshot.platform.vbs_configured = vbs.state;
    const RegistryDword hvci = ReadRegistryDword(
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
        L"HypervisorEnforcedCodeIntegrity",
        L"Enabled");
    snapshot.platform.hvci_configured = hvci.state;
    for (auto& service : snapshot.platform.services) {
        service.second = QueryService(
            std::wstring(service.first.begin(), service.first.end()).c_str());
    }
    QueryWhp(snapshot.platform);
    QueryProvider(snapshot.provider);
    return snapshot;
}

GateResult MakeGate(std::string name, GateState state, std::string reason) {
    GateResult result;
    result.name = std::move(name);
    result.state = state;
    result.reason = std::move(reason);
    return result;
}

std::vector<GateResult> EvaluateGates(const HostSnapshot& host,
                                      const std::wstring& profile) {
    std::vector<GateResult> gates;
    const bool host_only = profile == L"host-only";
    gates.push_back(MakeGate(
        "cpu.vmx", host.cpu.vmx ? GateState::Pass : GateState::Fail,
        host.cpu.vmx ? "CPUID VMX bit is set" : "CPUID VMX bit is clear"));
    gates.push_back(MakeGate(
        "cpu.topology", host.topology.complete ? GateState::Pass
                                                : GateState::Unknown,
        host.topology.complete ? "processor topology is readable"
                               : "processor topology is incomplete"));
    gates.push_back(MakeGate(
        "owner.hypervisor-bit",
        host.cpu.hypervisor_bit ? GateState::Fail : GateState::Pass,
        host.cpu.hypervisor_bit ? "CPUID reports an active hypervisor"
                                : "CPUID does not report a hypervisor"));
    gates.push_back(MakeGate(
        "platform.vmx-firmware", GateState::Unknown,
        "IA32_FEATURE_CONTROL is privileged and was not read in user mode"));
    gates.push_back(MakeGate(
        "platform.secure-boot", host.platform.secure_boot == TriState::Yes
                                    ? GateState::Pass
                                : host.platform.secure_boot == TriState::No
                                    ? GateState::Fail
                                    : GateState::Unknown,
        std::string("Secure Boot=") +
            TriStateText(host.platform.secure_boot)));
    gates.push_back(MakeGate(
        "platform.dmar", host.platform.dmar_table == TriState::Yes
                             ? GateState::Pass
                         : host.platform.dmar_table == TriState::No
                             ? GateState::Fail
                             : GateState::Unknown,
        std::string("ACPI DMAR table=") +
            TriStateText(host.platform.dmar_table)));
    gates.push_back(MakeGate(
        "platform.vbs-hvci",
        host.platform.vbs_configured == TriState::Yes ||
                host.platform.hvci_configured == TriState::Yes
            ? GateState::Fail
            : host.platform.vbs_configured == TriState::No &&
                      host.platform.hvci_configured == TriState::No
                  ? GateState::Pass
                  : GateState::Unknown,
        std::string("VBS=") + TriStateText(host.platform.vbs_configured) +
            ", HVCI=" + TriStateText(host.platform.hvci_configured)));
    gates.push_back(MakeGate(
        "provider.device",
        host.provider.device == TriState::Yes ? GateState::Pass
                                               : GateState::Unknown,
        host.provider.reason));
    gates.push_back(MakeGate(
        "provider.unique-owner",
        host.provider.unique_owner == TriState::Yes ? GateState::Pass
                                                    : GateState::Unknown,
        std::string("unique owner=") +
            TriStateText(host.provider.unique_owner)));
    gates.push_back(MakeGate(
        "provider.knhv-boot-l0",
        host.provider.knhv_boot_l0 == TriState::Yes ? GateState::Pass
                                                    : GateState::Unknown,
        std::string("KNHV_BOOT_L0=") +
            TriStateText(host.provider.knhv_boot_l0)));
    if (host_only) {
        gates.push_back(MakeGate(
            "profile.host-only", GateState::Pass,
            "host-only profile does not authorize hardware bring-up"));
    }
    return gates;
}

bool NativeReady(const std::vector<GateResult>& gates,
                 const std::wstring& profile) {
    if (profile == L"host-only") return false;
    for (const GateResult& gate : gates) {
        if (gate.name == "platform.vmx-firmware" ||
            gate.name == "provider.device" ||
            gate.name == "provider.unique-owner" ||
            gate.name == "provider.knhv-boot-l0") {
            if (gate.state != GateState::Pass) return false;
        } else if (gate.state != GateState::Pass) {
            return false;
        }
    }
    return true;
}

std::string Hex(std::uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::uppercase << value;
    return output.str();
}

std::string BuildJson(const HostSnapshot& host,
                      const std::wstring& profile,
                      const std::vector<GateResult>& gates,
                      bool ready, int exit_code) {
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\":\"knhv-preflight-1\",\n"
           << "  \"tool\":\"KNHV_Preflight\",\n"
           << "  \"created_at\":\"" << JsonEscape(NowIso8601())
           << "\",\n"
           << "  \"profile\":\"" << JsonEscape(Narrow(profile))
           << "\",\n"
           << "  \"status\":\""
           << (ready || profile == L"host-only" ? "pass" : "blocked")
           << "\",\n"
           << "  \"ready\":" << (ready ? "true" : "false") << ",\n"
           << "  \"exit_code\":" << exit_code << ",\n"
           << "  \"host\":{\"os_version\":\""
           << JsonEscape(host.platform.os_version)
           << "\",\"firmware_type\":\""
           << JsonEscape(host.platform.firmware_type)
           << "\",\"uefi\":\""
           << TriStateText(host.platform.uefi)
           << "\",\"secure_boot\":\""
           << TriStateText(host.platform.secure_boot)
           << "\",\"vbs_configured\":\""
           << TriStateText(host.platform.vbs_configured)
           << "\",\"hvci_configured\":\""
           << TriStateText(host.platform.hvci_configured)
           << "\",\"dmar_table\":\""
           << TriStateText(host.platform.dmar_table)
           << "\"},\n"
           << "  \"cpu\":{\"vendor\":\""
           << JsonEscape(host.cpu.vendor) << "\",\"brand\":\""
           << JsonEscape(host.cpu.brand) << "\",\"hypervisor_vendor\":\""
           << JsonEscape(host.cpu.hypervisor_vendor)
           << "\",\"vmx\":" << (host.cpu.vmx ? "true" : "false")
           << ",\"hypervisor_bit\":"
           << (host.cpu.hypervisor_bit ? "true" : "false")
           << ",\"invariant_tsc\":"
           << (host.cpu.invariant_tsc ? "true" : "false") << "},\n"
           << "  \"topology\":{\"processor_groups\":"
           << host.topology.processor_groups
           << ",\"logical_processors\":"
           << host.topology.logical_processors
           << ",\"physical_cores\":" << host.topology.physical_cores
           << ",\"complete\":"
           << (host.topology.complete ? "true" : "false") << "},\n"
           << "  \"platform\":{\"vmx_firmware\":\""
           << TriStateText(host.platform.vmx_firmware)
           << "\",\"whp_library\":\""
           << TriStateText(host.platform.whp_library)
           << "\",\"whp_api\":\""
           << TriStateText(host.platform.whp_api)
           << "\",\"whp_hypervisor\":\""
           << TriStateText(host.platform.whp_hypervisor) << "\"},\n"
           << "  \"provider\":{\"device\":\""
           << TriStateText(host.provider.device)
           << "\",\"unique_owner\":\""
           << TriStateText(host.provider.unique_owner)
           << "\",\"knhv_boot_l0\":\""
           << TriStateText(host.provider.knhv_boot_l0)
           << "\",\"nested_vmx\":\""
           << TriStateText(host.provider.nested_vmx)
           << "\",\"status\":" << host.provider.status
           << ",\"flags\":\"" << Hex(host.provider.flags)
           << "\",\"features\":\"" << Hex(host.provider.features)
           << "\",\"reason\":\""
           << JsonEscape(host.provider.reason) << "\"},\n"
           << "  \"services\":[";
    for (std::size_t index = 0; index < host.platform.services.size(); ++index) {
        if (index != 0U) output << ',';
        const auto& service = host.platform.services[index];
        output << "{\"name\":\"" << JsonEscape(service.first)
               << "\",\"present\":\""
               << TriStateText(service.second.present)
               << "\",\"running\":\""
               << TriStateText(service.second.running) << "\"}";
    }
    output << "],\n  \"gates\":[";
    for (std::size_t index = 0; index < gates.size(); ++index) {
        if (index != 0U) output << ',';
        const GateResult& gate = gates[index];
        output << "{\"name\":\"" << JsonEscape(gate.name)
               << "\",\"state\":\"" << GateStateText(gate.state)
               << "\",\"reason\":\"" << JsonEscape(gate.reason)
               << "\"}";
    }
    output << "],\n  \"actions\":[\"read-only collection only\","
               "\"no VMXON, BCD, driver load or DMA was performed\"]\n}\n";
    return output.str();
}

bool ParseOptions(int argc, wchar_t** argv, Options& options) {
    if (argv == nullptr || argc < 1) return false;
    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];
        if (argument == L"--help" || argument == L"-h") {
            options.help = true;
            return true;
        }
        if (argument == L"--out") {
            if (index + 1 >= argc || argv[index + 1] == nullptr) return false;
            options.output_path = argv[++index];
            if (options.output_path.empty()) return false;
            continue;
        }
        if (argument == L"--profile") {
            if (index + 1 >= argc || argv[index + 1] == nullptr) return false;
            options.profile = argv[++index];
            if (options.profile != L"native-l0" &&
                options.profile != L"host-only") {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

void PrintUsage() {
    std::wcout << L"KNHV_Preflight [--profile native-l0|host-only] [--out path]\n"
                  L"read-only capability and ownership preflight; no VMXON or "
                  L"system changes\n";
}

bool WriteOutput(const std::wstring& path, const std::string& text) {
    if (path.empty()) {
        std::cout << text;
        return true;
    }
    std::error_code error;
    const fs::path output_path(path);
    const fs::path parent = output_path.parent_path();
    if (!parent.empty()) fs::create_directories(parent, error);
    if (error) return false;
    std::ofstream file(output_path, std::ios::binary);
    if (!file) return false;
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    return file.good();
}

}  // namespace

int Run(int argc, wchar_t** argv) {
    Options options;
    if (!ParseOptions(argc, argv, options)) {
        PrintUsage();
        return kExitInvalid;
    }
    if (options.help) {
        PrintUsage();
        return 0;
    }
    const HostSnapshot host = CollectHost();
    const std::vector<GateResult> gates =
        EvaluateGates(host, options.profile);
    const bool ready = NativeReady(gates, options.profile);
    const int exit_code = options.profile == L"host-only"
                              ? kExitSuccess
                              : (ready ? kExitSuccess : kExitBlocked);
    const std::string json =
        BuildJson(host, options.profile, gates, ready, exit_code);
    if (!WriteOutput(options.output_path, json)) return kExitInvalid;
    return exit_code;
}

}  // namespace knhv_preflight
