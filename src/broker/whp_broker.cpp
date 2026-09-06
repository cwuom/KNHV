#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>

#include "knhv_whp.h"

namespace {

namespace fs = std::filesystem;

constexpr int kExitSuccess = 0;
constexpr int kExitBlocked = 10;
constexpr int kExitInvalid = 11;
constexpr int kCapabilityHypervisorPresent = 0x00000000;
constexpr int kCapabilityFeatures = 0x00000001;
constexpr int kCapabilityExtendedVmExits = 0x00000002;
constexpr int kCapabilityProcessorClock = 0x00001004;
constexpr int kCapabilityPhysicalAddressWidth = 0x0000100A;
constexpr int kCapabilityVmxBasic = 0x00002000;

using GetCapabilityFn = HRESULT(WINAPI*)(int, void*, UINT32, UINT32*);

struct Options {
    bool help = false;
    bool run_requested = false;
    fs::path output;
};

struct ProbeResult {
    bool library_present = false;
    bool api_present = false;
    bool hypervisor_present = false;
    bool hypervisor_known = false;
    bool features_known = false;
    bool extended_exits_known = false;
    bool clock_known = false;
    bool physical_width_known = false;
    bool nested_capability_queried = false;
    bool nested_capability_nonzero = false;
    HRESULT last_error = S_OK;
    UINT32 feature_written = 0;
    UINT32 exit_written = 0;
    UINT32 nested_written = 0;
    UINT32 physical_width_written = 0;
    UINT32 clock_written = 0;
    std::uint64_t whp_features = 0;
    std::uint64_t whp_extended_exits = 0;
    std::uint64_t clock_hz = 0;
    std::uint32_t physical_address_bits = 0;
    std::uint32_t max_vcpus = 0;
};

void PrintUsage() {
    std::cout
        << "KNHV_WHPBroker [--caps-only] [--out path] [--run] [--help]\n"
        << "  --caps-only  query WinHvPlatform without creating a partition\n"
        << "  --run        reserved and fail-closed until the WHP runner is enabled\n";
}

bool ParseOptions(int argc, char** argv, Options& options) {
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            options.help = true;
        } else if (argument == "--caps-only") {
            continue;
        } else if (argument == "--run") {
            options.run_requested = true;
        } else if (argument == "--out" && index + 1 < argc) {
            options.output = argv[++index];
        } else {
            return false;
        }
    }
    return true;
}

template <typename T>
bool QueryCapabilityValue(GetCapabilityFn query, int code, T& value,
                          UINT32& written, HRESULT& last_error) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "WHP capability values must be trivially copyable");
    value = {};
    written = 0;
    const UINT32 size = static_cast<UINT32>(sizeof(value));
    const HRESULT error = query(code, &value, size, &written);
    if (FAILED(error) || written < size) {
        last_error = error;
        return false;
    }
    return true;
}

void MapFeatures(const ProbeResult& probe, knhv::WhpCapabilities& capabilities) {
    if (probe.hypervisor_known && probe.hypervisor_present) {
        capabilities.feature_flags |= knhv::kWhpCapPartition;
    }
    if ((probe.whp_features & (1ULL << 1)) != 0) {
        capabilities.feature_flags |= knhv::kWhpCapLocalApic;
    }
    if ((probe.whp_features & (1ULL << 2)) != 0) {
        capabilities.feature_flags |= knhv::kWhpCapXsave;
    }
    if ((probe.whp_features & (1ULL << 3)) != 0) {
        capabilities.feature_flags |= knhv::kWhpCapDirtyPageTracking;
    }
    if ((probe.whp_features & (1ULL << 7)) != 0) {
        capabilities.feature_flags |= knhv::kWhpCapVirtualPci;
    }
    if ((probe.whp_features & (1ULL << 8)) != 0) {
        capabilities.feature_flags |= knhv::kWhpCapIommu;
    }
    if (probe.clock_known && probe.clock_hz != 0) {
        capabilities.feature_flags |= knhv::kWhpCapReferenceTime;
    }
    if (probe.extended_exits_known) {
        capabilities.feature_flags |= knhv::kWhpCapExtendedExits;
    }
}

ProbeResult ProbeWhp(GetCapabilityFn query) {
    ProbeResult result;
    BOOL present = FALSE;
    HRESULT error = S_OK;
    if (QueryCapabilityValue(query, kCapabilityHypervisorPresent, present,
                             result.feature_written, error)) {
        result.hypervisor_known = true;
        result.hypervisor_present = present != FALSE;
    } else {
        result.last_error = error;
    }

    result.features_known = QueryCapabilityValue(
        query, kCapabilityFeatures, result.whp_features,
        result.feature_written, error);
    if (!result.features_known) {
        result.last_error = error;
    }
    result.extended_exits_known = QueryCapabilityValue(
        query, kCapabilityExtendedVmExits, result.whp_extended_exits,
        result.exit_written, error);
    if (!result.extended_exits_known) {
        result.last_error = error;
    }
    result.clock_known = QueryCapabilityValue(
        query, kCapabilityProcessorClock, result.clock_hz,
        result.clock_written, error);
    if (!result.clock_known) {
        result.last_error = error;
    }
    result.physical_width_known = QueryCapabilityValue(
        query, kCapabilityPhysicalAddressWidth, result.physical_address_bits,
        result.physical_width_written, error);
    if (!result.physical_width_known) {
        result.last_error = error;
    }
    std::uint64_t nested = 0;
    result.nested_capability_queried = QueryCapabilityValue(
        query, kCapabilityVmxBasic, nested, result.nested_written, error);
    result.nested_capability_nonzero = result.nested_capability_queried &&
                                       nested != 0;
    if (!result.nested_capability_queried) result.last_error = error;

    const DWORD active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    result.max_vcpus = active == 0
                           ? 0
                           : static_cast<std::uint32_t>(
                                 active > knhv::kWhpMaxVcpus
                                     ? knhv::kWhpMaxVcpus
                                     : active);
    return result;
}

bool RequiredQueriesPresent(const ProbeResult& probe) {
    return probe.hypervisor_known && probe.features_known &&
           probe.physical_width_known && probe.max_vcpus != 0;
}

std::uint32_t ErrorValue(HRESULT error) {
    return static_cast<std::uint32_t>(error);
}

std::string BuildJson(const ProbeResult& probe,
                      const knhv::WhpCapabilities& caps,
                      bool run_requested, const char* verdict,
                      const char* reason) {
    std::ostringstream output;
    output << R"({"schema":"knhv-whp-probe-1",)"
           << "\"mode\":\"caps-only\",\"verdict\":\"" << verdict
           << "\",\"reason\":\"" << reason << "\","
           << "\"library_present\":"
           << (probe.library_present ? "true" : "false") << ','
           << "\"api_present\":" << (probe.api_present ? "true" : "false")
           << ','
           << "\"required_queries_ok\":"
           << (RequiredQueriesPresent(probe) ? "true" : "false") << ','
           << "\"hypervisor_present\":"
           << (probe.hypervisor_present ? "true" : "false") << ','
           << "\"hypervisor_known\":"
           << (probe.hypervisor_known ? "true" : "false") << ','
           << "\"whp_features\":\"0x" << std::hex << probe.whp_features
           << "\",\"extended_exits\":\"0x" << probe.whp_extended_exits
           << "\",\"model_features\":\"0x" << caps.feature_flags
           << "\",\"clock_hz\":" << std::dec << probe.clock_hz
           << ",\"physical_address_bits\":"
           << probe.physical_address_bits << ",\"max_vcpus\":"
           << probe.max_vcpus << ",\"nested_capability_queried\":"
           << (probe.nested_capability_queried ? "true" : "false")
           << ",\"nested_capability_nonzero\":"
           << (probe.nested_capability_nonzero ? "true" : "false")
           << ",\"model_valid\":"
           << (knhv::IsWhpCapabilitiesValid(&caps) ? "true" : "false")
           << ",\"last_error\":\"0x" << std::hex
           << ErrorValue(probe.last_error) << std::dec << '\"'
           << ",\"snapshot_generation\":" << caps.generation
           << ",\"feature_written\":" << probe.feature_written
           << ",\"exit_written\":" << probe.exit_written
           << ",\"clock_written\":" << probe.clock_written
           << ",\"physical_width_written\":"
           << probe.physical_width_written
           << ",\"nested_written\":" << probe.nested_written
           << ",\"partition_create_attempted\":false"
           << ",\"run_requested\":"
           << (run_requested ? "true" : "false") << "}";
    return output.str();
}

std::string BuildBlockedJson(const char* mode, const char* reason,
                             bool run_requested) {
    std::ostringstream output;
    output << R"({"schema":"knhv-whp-probe-1",)"
           << "\"mode\":\"" << mode << "\",\"verdict\":\"blocked\","
           << "\"reason\":\"" << reason << "\","
           << "\"library_present\":false,\"api_present\":false,"
           << "\"model_valid\":false,\"partition_create_attempted\":false,"
           << "\"run_requested\":"
           << (run_requested ? "true" : "false") << "}";
    return output.str();
}


int WriteOutput(const fs::path& path, const std::string& text) {
    if (path.empty()) {
        std::cout << text << '\n';
        return kExitSuccess;
    }
    std::error_code error;
    const fs::path parent = path.parent_path();
    if (!parent.empty()) fs::create_directories(parent, error);
    if (error) return kExitInvalid;
    std::ofstream file(path, std::ios::binary);
    if (!file) return kExitInvalid;
    file << text << '\n';
    return file.good() ? kExitSuccess : kExitInvalid;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!ParseOptions(argc, argv, options)) {
        PrintUsage();
        return kExitInvalid;
    }
    if (options.help) {
        PrintUsage();
        return kExitSuccess;
    }
    if (options.run_requested) {
        const int code = WriteOutput(
            options.output,
            BuildBlockedJson("run", "partition runner is not enabled in this build",
                             true));
        return code == kExitSuccess ? kExitBlocked : code;
    }

    HMODULE library = LoadLibraryExW(L"WinHvPlatform.dll", nullptr,
                                     LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (library == nullptr) {
        const int code = WriteOutput(
            options.output,
            BuildBlockedJson("caps-only", "WinHvPlatform.dll unavailable", false));
        return code == kExitSuccess ? kExitBlocked : code;
    }
    const auto query = reinterpret_cast<GetCapabilityFn>(
        GetProcAddress(library, "WHvGetCapability"));
    if (query == nullptr) {
        FreeLibrary(library);
        const int code = WriteOutput(
            options.output,
            BuildBlockedJson("caps-only", "WHvGetCapability unavailable", false));
        return code == kExitSuccess ? kExitBlocked : code;
    }
    ProbeResult probe = ProbeWhp(query);
    probe.library_present = true;
    probe.api_present = true;
    knhv::WhpCapabilities capabilities = {};
    capabilities.size = sizeof(capabilities);
    capabilities.version = knhv::kWhpContractVersion;
    capabilities.api_version = 1U;
    capabilities.generation = GetTickCount64();
    if (capabilities.generation == 0ULL) capabilities.generation = 1ULL;
    MapFeatures(probe, capabilities);
    capabilities.extended_exit_flags = probe.whp_extended_exits;
    capabilities.processor_clock_hz = probe.clock_hz;
    capabilities.physical_address_bits = probe.physical_address_bits;
    capabilities.max_vcpus = probe.max_vcpus;
    const bool model_valid = knhv::IsWhpCapabilitiesValid(&capabilities);
    const std::string json = BuildJson(
        probe, capabilities, false, model_valid ? "pass" : "blocked",
        model_valid ? "capability snapshot is valid"
                    : "required WHP capability is unavailable");
    const int code = WriteOutput(options.output, json);
    FreeLibrary(library);
    if (code != kExitSuccess) return code;
    return model_valid ? kExitSuccess : kExitBlocked;
}
