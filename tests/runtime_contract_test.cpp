#include "test_support.h"

#include <intrin.h>
#include <softpub.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")

namespace knhv_tests {
namespace {

template <typename T>
bool ReadObject(const std::vector<std::uint8_t>& bytes, std::size_t offset,
                T& object) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        return false;
    }
    std::memcpy(&object, bytes.data() + offset, sizeof(T));
    return true;
}

std::vector<std::uint8_t> ReadBinary(const fs::path& path, TestState& state) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        Check(state, "driver artifact is readable", false,
              path.generic_string());
        return {};
    }
    file.seekg(0, std::ios::end);
    if (!file) {
        Check(state, "driver artifact size is readable", false,
              path.generic_string());
        return {};
    }
    const std::streamoff size = file.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) >
                        (std::numeric_limits<std::size_t>::max)()) {
        Check(state, "driver artifact size is representable", false,
              path.generic_string());
        return {};
    }
    file.seekg(0, std::ios::beg);
    if (!file) {
        Check(state, "driver artifact can be rewound", false,
              path.generic_string());
        return {};
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        file.read(reinterpret_cast<char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    const bool complete_read =
        bytes.empty() ||
        file.gcount() == static_cast<std::streamsize>(bytes.size());
    Check(state, "driver artifact is readable", complete_read,
          path.generic_string());
    if (!complete_read) return {};
    return bytes;
}

bool ContainsBytes(const std::vector<std::uint8_t>& bytes,
                   std::initializer_list<std::uint8_t> needle) {
    if (needle.empty() || bytes.size() < needle.size()) return false;
    for (std::size_t offset = 0;
         offset + needle.size() <= bytes.size(); ++offset) {
        std::size_t index = 0;
        bool match = true;
        for (const std::uint8_t expected : needle) {
            if (bytes[offset + index] != expected) {
                match = false;
                break;
            }
            ++index;
        }
        if (match) return true;
    }
    return false;
}

bool RvaToFileOffset(const std::vector<std::uint8_t>& bytes,
                     const IMAGE_SECTION_HEADER* sections,
                     WORD section_count, DWORD rva, std::size_t& offset) {
    if (!sections) return false;
    for (WORD index = 0; index < section_count; ++index) {
        const IMAGE_SECTION_HEADER& section = sections[index];
        const DWORD span = (std::max)(section.Misc.VirtualSize,
                                      section.SizeOfRawData);
        if (rva < section.VirtualAddress ||
            rva - section.VirtualAddress >= span) {
            continue;
        }
        const std::uint64_t raw =
            static_cast<std::uint64_t>(section.PointerToRawData) +
            (rva - section.VirtualAddress);
        if (raw >= bytes.size()) return false;
        offset = static_cast<std::size_t>(raw);
        return true;
    }
    return false;
}

void CheckPeImage(const fs::path& driver, TestState& state) {
    const std::vector<std::uint8_t> bytes = ReadBinary(driver, state);
    if (bytes.empty()) {
        if (fs::is_regular_file(driver)) {
            Check(state, "SYS is not empty", false, driver.string());
        }
        return;
    }
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        Check(state, "SYS contains a complete DOS header", false,
              driver.string());
        return;
    }

    IMAGE_DOS_HEADER dos{};
    const bool dos_ok = ReadObject(bytes, 0, dos) &&
                        dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= 0;
    Check(state, "SYS has a valid DOS header", dos_ok, driver.string());
    if (!dos_ok) return;

    const std::size_t pe_offset = static_cast<std::size_t>(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header{};
    if (!ReadObject(bytes, pe_offset, signature) ||
        signature != IMAGE_NT_SIGNATURE ||
        !ReadObject(bytes, pe_offset + sizeof(DWORD), file_header)) {
        Check(state, "SYS has a valid PE header", false, driver.string());
        return;
    }
    Check(state, "SYS has a valid PE header", true);
    Check(state, "SYS targets AMD64", file_header.Machine == IMAGE_FILE_MACHINE_AMD64);

    const std::size_t optional_offset = pe_offset + sizeof(DWORD) +
                                        sizeof(IMAGE_FILE_HEADER);
    const bool optional_header_fits =
        file_header.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64) &&
        optional_offset <= bytes.size() &&
        file_header.SizeOfOptionalHeader <= bytes.size() - optional_offset;
    WORD optional_magic = 0;
    if (!optional_header_fits || !ReadObject(bytes, optional_offset, optional_magic) ||
        optional_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        Check(state, "SYS has a PE32+ optional header", false,
              driver.string());
        return;
    }
    Check(state, "SYS has a PE32+ optional header", true);

    IMAGE_OPTIONAL_HEADER64 optional_header{};
    if (!ReadObject(bytes, optional_offset, optional_header)) return;
    Check(state, "SYS uses the native driver subsystem",
          optional_header.Subsystem == IMAGE_SUBSYSTEM_NATIVE);

    const std::size_t section_offset =
        optional_offset + file_header.SizeOfOptionalHeader;
    const std::uint64_t section_bytes =
        static_cast<std::uint64_t>(file_header.NumberOfSections) *
        sizeof(IMAGE_SECTION_HEADER);
    if (section_offset > bytes.size() ||
        section_bytes > bytes.size() - section_offset) {
        Check(state, "SYS section table fits the file", false, driver.string());
        return;
    }
    Check(state, "SYS section table fits the file", true);
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        bytes.data() + section_offset);
    const IMAGE_DATA_DIRECTORY debug_directory =
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    bool debug_present = debug_directory.VirtualAddress != 0 &&
                         debug_directory.Size >= sizeof(IMAGE_DEBUG_DIRECTORY);
    std::string pdb_name;
    if (debug_present) {
        std::size_t debug_offset = 0;
        if (!RvaToFileOffset(bytes, sections, file_header.NumberOfSections,
                             debug_directory.VirtualAddress, debug_offset)) {
            debug_present = false;
        } else {
            const std::size_t entry_count =
                debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            debug_present = false;
            for (std::size_t index = 0; index < entry_count; ++index) {
                IMAGE_DEBUG_DIRECTORY debug{};
                const std::size_t entry_offset =
                    debug_offset + index * sizeof(IMAGE_DEBUG_DIRECTORY);
                if (!ReadObject(bytes, entry_offset, debug) ||
                    debug.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
                    debug.PointerToRawData == 0 || debug.SizeOfData < 24) {
                    continue;
                }
                const std::size_t cv_offset = debug.PointerToRawData;
                if (cv_offset > bytes.size() ||
                    debug.SizeOfData > bytes.size() - cv_offset ||
                    std::memcmp(bytes.data() + cv_offset, "RSDS", 4) != 0) {
                    continue;
                }
                const char* path = reinterpret_cast<const char*>(
                    bytes.data() + cv_offset + 24);
                const std::size_t available =
                    debug.SizeOfData - 24;
                const std::size_t length = strnlen_s(path, available);
                if (length < available) {
                    pdb_name.assign(path, length);
                    debug_present = true;
                    break;
                }
            }
        }
    }
    Check(state, "SYS carries CodeView debug metadata", debug_present,
          driver.string());
    const bool has_field_value_vmwrite =
        ContainsBytes(bytes, {0x0F, 0x79, 0xCA, 0x9C, 0x58, 0xC3});
    const bool has_value_field_vmwrite =
        ContainsBytes(bytes, {0x0F, 0x79, 0xD1, 0x9C, 0x58, 0xC3});
    Check(state, "SYS contains the field-value VMWRITE ABI",
          has_field_value_vmwrite && !has_value_field_vmwrite,
          "expected vmwrite rcx, rdx encoding");
    const fs::path expected_pdb = driver.parent_path() /
                                  (driver.stem().wstring() + L".pdb");
    Check(state, "matching PDB is present",
          fs::exists(expected_pdb) && fs::file_size(expected_pdb) > 0,
          expected_pdb.generic_string());
    if (!pdb_name.empty()) {
        const std::string expected_name = expected_pdb.filename().string();
        Check(state, "CodeView names the matching PDB",
              pdb_name.size() >= expected_name.size() &&
                  _stricmp(pdb_name.c_str() +
                               (pdb_name.size() - expected_name.size()),
                           expected_name.c_str()) == 0,
              pdb_name);
    }
}

bool IsPrivateTestRoot(LONG status) {
    return status == TRUST_E_SUBJECT_NOT_TRUSTED ||
           status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING ||
           status == CERT_E_UNTRUSTEDTESTROOT;
}

void CheckSignature(const fs::path& driver, bool allow_test_root,
                    TestState& state) {
    const std::wstring path = driver.wstring();
    WINTRUST_FILE_INFO file{sizeof(file), path.c_str(), nullptr, nullptr};
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &policy, &data);

    const bool trusted = status == ERROR_SUCCESS;
    const bool accepted = trusted || (allow_test_root && IsPrivateTestRoot(status));
    Check(state, "SYS signature is verifiable", accepted,
          trusted ? "trusted" : "private test root is not trusted here");
}

void CheckHardware(TestState& state) {
    int leaf0[4]{};
    __cpuidex(leaf0, 0, 0);
    const std::uint32_t max_basic = static_cast<std::uint32_t>(leaf0[0]);
    Check(state, "CPUID leaf 1 is available", max_basic >= 1);
    if (max_basic < 1) return;

    const std::string vendor =
        std::string(reinterpret_cast<const char*>(&leaf0[1]), 4) +
        std::string(reinterpret_cast<const char*>(&leaf0[3]), 4) +
        std::string(reinterpret_cast<const char*>(&leaf0[2]), 4);
    Check(state, "processor vendor is Intel", vendor == "GenuineIntel", vendor);

    int leaf1[4]{};
    __cpuidex(leaf1, 1, 0);
    Check(state, "Intel VMX is enumerated", (leaf1[2] & (1U << 5)) != 0);
    Check(state, "no outer hypervisor is enumerated",
          (static_cast<std::uint32_t>(leaf1[2]) & (1U << 31)) == 0);
    const bool xsave = (leaf1[2] & (1U << 26)) != 0;
    const bool osxsave = (leaf1[2] & (1U << 27)) != 0;
    Check(state, "legacy FXSAVE is enumerated", (leaf1[3] & (1U << 24)) != 0);
    if (!xsave || !osxsave || max_basic < 0xD) return;

    const std::uint64_t xcr0 = _xgetbv(0);
    Check(state, "XCR0 contains x87 and SSE", (xcr0 & 3ULL) == 3ULL);
    int leaf_d0[4]{};
    __cpuidex(leaf_d0, 0xD, 0);
    Check(state, "XSAVE area fits the exit frame",
          static_cast<std::uint32_t>(leaf_d0[1]) <= 0x1000U);
    std::cout << "Hardware: XCR0=0x" << std::hex << xcr0 << std::dec << "\n";
}

bool WaitForService(SC_HANDLE service, DWORD expected, DWORD timeout_ms) {
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    do {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&status),
                                  sizeof(status), &bytes)) {
            return false;
        }
        if (status.dwCurrentState == expected) return true;
        Sleep(100);
    } while (GetTickCount64() < deadline);
    return false;
}

void CheckService(const std::wstring& name, bool start, bool stop,
                  TestState& state) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    Check(state, "service manager is accessible", manager != nullptr,
          std::to_string(GetLastError()));
    if (!manager) return;

    SC_HANDLE service = OpenServiceW(
        manager, name.c_str(),
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
    Check(state, "driver service is installed", service != nullptr,
          std::to_string(GetLastError()));
    if (!service) {
        CloseServiceHandle(manager);
        return;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    const bool queried = QueryServiceStatusEx(
        service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
        sizeof(status), &bytes) != FALSE;
    Check(state, "driver service status is queryable", queried);
    bool running = queried && status.dwCurrentState == SERVICE_RUNNING;
    bool started_by_test = false;
    if (start) {
        const BOOL result = StartServiceW(service, 0, nullptr);
        const DWORD error = result ? ERROR_SUCCESS : GetLastError();
        const bool accepted = result || error == ERROR_SERVICE_ALREADY_RUNNING;
        Check(state, "driver start request is accepted", accepted,
              std::to_string(error));
        started_by_test = result != FALSE;
        running = accepted && WaitForService(service, SERVICE_RUNNING, 10000);
        Check(state, "driver reaches RUNNING", running);
    }
    if (stop && started_by_test) {
        SERVICE_STATUS ignored{};
        const BOOL result = ControlService(service, SERVICE_CONTROL_STOP, &ignored);
        Check(state, "driver stop request succeeds", result != FALSE,
              std::to_string(GetLastError()));
        if (result) {
            Check(state, "driver reaches STOPPED",
                  WaitForService(service, SERVICE_STOPPED, 10000));
        }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
}

}  // namespace

void RunArtifactContract(const fs::path& root, const fs::path& driver,
                         TestState& state) {
    UNREFERENCED_PARAMETER(root);
    CheckPeImage(driver, state);
}

void RunSignatureContract(const fs::path& driver, bool allow_test_root,
                          TestState& state) {
    CheckSignature(driver, allow_test_root, state);
}

void RunHardwareContract(TestState& state) { CheckHardware(state); }

void RunServiceContract(const std::wstring& name, bool start, bool stop,
                        TestState& state) {
    CheckService(name, start, stop, state);
}

}  // namespace knhv_tests
