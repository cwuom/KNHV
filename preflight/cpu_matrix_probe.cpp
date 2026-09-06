#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <intrin.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "knhv_cpu_matrix.h"

namespace {

namespace fs = std::filesystem;

constexpr int kExitSuccess = 0;
constexpr int kExitBlocked = 10;
constexpr int kExitInvalid = 11;
constexpr std::uint64_t kRequiredFeatures =
    knhv::kCpuMatrixFeatureVmx | knhv::kCpuMatrixFeatureInvariantTsc;
constexpr unsigned kAffinityBits = sizeof(KAFFINITY) * 8U;

constexpr std::uint32_t kLeaf1EcxVmx = 1U << 5;
constexpr std::uint32_t kLeaf1EcxPcide = 1U << 17;
constexpr std::uint32_t kLeaf1EcxTscDeadline = 1U << 24;
constexpr std::uint32_t kLeaf1EcxXsave = 1U << 26;
constexpr std::uint32_t kLeaf1EcxHypervisor = 1U << 31;
constexpr std::uint32_t kLeaf7EbxFsgsbase = 1U << 0;
constexpr std::uint32_t kLeaf7EbxSmep = 1U << 7;
constexpr std::uint32_t kLeaf7EbxInvpcid = 1U << 10;
constexpr std::uint32_t kLeaf7EbxSmap = 1U << 20;
constexpr std::uint32_t kLeaf7EcxCetIbt = 1U << 20;
constexpr std::uint32_t kExtendedLeaf7EdxInvariantTsc = 1U << 8;

struct LogicalProcessor {
    WORD group = 0;
    std::uint32_t number = 0;
    std::uint32_t index = 0;
};

struct Options {
    fs::path output;
    std::uint32_t max_processors = knhv::kCpuMatrixMaxProcessors;
    bool help = false;
};

struct Collection {
    std::vector<knhv::CpuMatrixSample> samples;
    std::uint32_t expected_count = 0;
    std::uint32_t collection_limit = knhv::kCpuMatrixMaxProcessors;
    bool truncated = false;
    bool affinity_saved = false;
    bool affinity_restored = false;
    DWORD affinity_error = ERROR_SUCCESS;
};

struct CpuidResult {
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
};

std::string JsonEscape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8U);
    for (const unsigned char character : value) {
        switch (character) {
            case '\\':
                result += "\\\\";
                break;
            case '"':
                result += "\\\"";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                if (character < 0x20U) {
                    std::ostringstream escaped;
                    escaped << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0')
                            << static_cast<unsigned>(character);
                    result += escaped.str();
                } else {
                    result.push_back(static_cast<char>(character));
                }
                break;
        }
    }
    return result;
}

std::string Hex(std::uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::uppercase << value;
    return output.str();
}

std::string NowIso8601() {
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << utc.wYear << '-'
           << std::setw(2) << utc.wMonth << '-' << std::setw(2)
           << utc.wDay << 'T' << std::setw(2) << utc.wHour << ':'
           << std::setw(2) << utc.wMinute << ':' << std::setw(2)
           << utc.wSecond << '.' << std::setw(3) << utc.wMilliseconds
           << 'Z';
    return output.str();
}

const char* StateText(std::uint32_t state) {
    switch (static_cast<knhv::CpuMatrixState>(state)) {
        case knhv::CpuMatrixState::Empty:
            return "empty";
        case knhv::CpuMatrixState::CompleteUniform:
            return "complete-uniform";
        case knhv::CpuMatrixState::CompleteMixed:
            return "complete-mixed";
        case knhv::CpuMatrixState::Incomplete:
            return "incomplete";
        default:
            return "invalid";
    }
}

bool ParseUnsigned(std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    std::string copy(text);
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(copy.c_str(), &end, 0);
    if (errno == ERANGE || end == copy.c_str() || *end != '\0') return false;
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool ParseOptions(int argc, char** argv, Options& options) {
    if (argv == nullptr || argc < 1) return false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            options.help = true;
            return true;
        }
        if (argument == "--out") {
            if (index + 1 >= argc || argv[index + 1] == nullptr ||
                argv[index + 1][0] == '\0') {
                return false;
            }
            options.output = fs::path(argv[++index]);
            continue;
        }
        if (argument == "--max-cpus") {
            if (index + 1 >= argc || argv[index + 1] == nullptr) return false;
            std::uint64_t parsed = 0;
            if (!ParseUnsigned(argv[++index], parsed) || parsed == 0 ||
                parsed > knhv::kCpuMatrixMaxProcessors) {
                return false;
            }
            options.max_processors = static_cast<std::uint32_t>(parsed);
            continue;
        }
        return false;
    }
    return true;
}

void PrintUsage() {
    std::cout
        << "KNHV_CpuMatrix [--out path] [--max-cpus count] [--help]\n"
        << "read-only per-processor CPUID matrix; no VMX, MSR, driver, or DMA\n";
}

std::vector<LogicalProcessor> EnumerateProcessors() {
    std::vector<LogicalProcessor> processors;
    const WORD group_count = GetActiveProcessorGroupCount();
    std::uint32_t index = 0;
    for (WORD group = 0; group < group_count; ++group) {
        const DWORD count = GetActiveProcessorCount(group);
        for (DWORD number = 0; number < count; ++number) {
            processors.push_back(
                {group, static_cast<std::uint32_t>(number), index++});
        }
    }
    return processors;
}

void ReadCurrentProcessor(PROCESSOR_NUMBER& processor) {
    processor = {};
    GetCurrentProcessorNumberEx(&processor);
}

bool IsCurrentProcessor(const PROCESSOR_NUMBER& processor,
                        const LogicalProcessor& expected) {
    return processor.Group == expected.group &&
           processor.Number == expected.number;
}

bool PinCurrentThread(const LogicalProcessor& processor, DWORD& error) {
    if (processor.number >= kAffinityBits) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }
    GROUP_AFFINITY affinity{};
    affinity.Group = processor.group;
    affinity.Mask = static_cast<KAFFINITY>(1) << processor.number;
    if (SetThreadGroupAffinity(GetCurrentThread(), &affinity, nullptr) ==
        FALSE) {
        error = GetLastError();
        return false;
    }
    PROCESSOR_NUMBER current{};
    ReadCurrentProcessor(current);
    if (!IsCurrentProcessor(current, processor)) {
        error = ERROR_PROCESS_ABORTED;
        return false;
    }
    return true;
}

bool RestoreAffinity(const GROUP_AFFINITY& original, Collection& collection) {
    GROUP_AFFINITY ignored_previous{};
    if (SetThreadGroupAffinity(GetCurrentThread(), &original,
                               &ignored_previous) == FALSE) {
        collection.affinity_restored = false;
        collection.affinity_error = GetLastError();
        return false;
    }
    collection.affinity_restored = true;
    return true;
}

CpuidResult ReadCpuid(std::uint32_t leaf, std::uint32_t subleaf) {
    std::array<int, 4> registers{};
    __cpuidex(registers.data(), static_cast<int>(leaf),
              static_cast<int>(subleaf));
    return {static_cast<std::uint32_t>(registers[0]),
            static_cast<std::uint32_t>(registers[1]),
            static_cast<std::uint32_t>(registers[2]),
            static_cast<std::uint32_t>(registers[3])};
}

void SetFeatureFlags(knhv::CpuMatrixSample& sample, const CpuidResult& leaf1,
                     const CpuidResult& leaf7,
                     const CpuidResult& extended_leaf7) {
    if ((leaf1.ecx & kLeaf1EcxVmx) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureVmx;
    }
    if ((leaf1.ecx & kLeaf1EcxHypervisor) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureHypervisor;
    }
    if ((leaf1.ecx & kLeaf1EcxXsave) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureXsave;
    }
    if ((leaf1.ecx & kLeaf1EcxPcide) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeaturePcide;
    }
    if ((leaf1.ecx & kLeaf1EcxTscDeadline) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureTscDeadline;
    }
    if ((leaf7.ebx & kLeaf7EbxInvpcid) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureInvpcid;
    }
    if ((leaf7.ebx & kLeaf7EbxFsgsbase) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureFsgsbase;
    }
    if ((leaf7.ebx & kLeaf7EbxSmep) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureSmep;
    }
    if ((leaf7.ebx & kLeaf7EbxSmap) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureSmap;
    }
    if ((leaf7.ecx & kLeaf7EcxCetIbt) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureCetIbt;
    }
    if ((extended_leaf7.edx & kExtendedLeaf7EdxInvariantTsc) != 0) {
        sample.feature_flags |= knhv::kCpuMatrixFeatureInvariantTsc;
    }
}

knhv::CpuMatrixSample CollectSample(const LogicalProcessor& processor) {
    knhv::CpuMatrixSample sample{};
    sample.size = sizeof(sample);
    sample.version = knhv::kCpuMatrixContractVersion;
    sample.logical_index = processor.index;
    sample.processor_group = processor.group;
    sample.processor_number = processor.number;

    PROCESSOR_NUMBER current_before{};
    ReadCurrentProcessor(current_before);
    if (!IsCurrentProcessor(current_before, processor)) {
        sample.status |= knhv::kCpuMatrixSampleMigrated;
        return sample;
    }

    const CpuidResult basic = ReadCpuid(0, 0);
    sample.max_basic_leaf = basic.eax;
    sample.vendor_ebx = basic.ebx;
    sample.vendor_ecx = basic.ecx;
    sample.vendor_edx = basic.edx;

    CpuidResult leaf1{};
    CpuidResult leaf7{};
    CpuidResult extended_leaf7{};
    if (sample.max_basic_leaf >= 1U) {
        leaf1 = ReadCpuid(1, 0);
        sample.leaf1_ecx = leaf1.ecx;
        sample.leaf1_edx = leaf1.edx;
    }
    if (sample.max_basic_leaf >= 7U) {
        leaf7 = ReadCpuid(7, 0);
        sample.leaf7_max_subleaf = leaf7.eax;
        sample.leaf7_ebx = leaf7.ebx;
        sample.leaf7_ecx = leaf7.ecx;
        sample.leaf7_edx = leaf7.edx;
    }

    const CpuidResult extended = ReadCpuid(0x80000000U, 0);
    sample.max_extended_leaf = extended.eax;
    if (sample.max_extended_leaf >= 0x80000007U) {
        extended_leaf7 = ReadCpuid(0x80000007U, 0);
        sample.extended_leaf7_edx = extended_leaf7.edx;
    }
    if (sample.max_extended_leaf >= 0x80000008U) {
        const CpuidResult extended_leaf8 = ReadCpuid(0x80000008U, 0);
        sample.extended_leaf8_eax = extended_leaf8.eax;
        sample.physical_address_bits = extended_leaf8.eax & 0xFFU;
        sample.linear_address_bits = (extended_leaf8.eax >> 8U) & 0xFFU;
    }
    if ((leaf1.ecx & kLeaf1EcxHypervisor) != 0) {
        const CpuidResult hypervisor = ReadCpuid(0x40000000U, 0);
        if (hypervisor.eax >= 0x40000000U) {
            sample.hypervisor_ebx = hypervisor.ebx;
            sample.hypervisor_ecx = hypervisor.ecx;
            sample.hypervisor_edx = hypervisor.edx;
        }
    }
    SetFeatureFlags(sample, leaf1, leaf7, extended_leaf7);

    PROCESSOR_NUMBER current_after{};
    ReadCurrentProcessor(current_after);
    if (!IsCurrentProcessor(current_after, processor)) {
        sample.status |= knhv::kCpuMatrixSampleMigrated;
        return sample;
    }
    if (sample.max_basic_leaf < 1U ||
        sample.max_extended_leaf < 0x80000000U ||
        (sample.vendor_ebx == 0U && sample.vendor_ecx == 0U &&
         sample.vendor_edx == 0U)) {
        sample.status |= knhv::kCpuMatrixSampleCpuidFailed;
        return sample;
    }
    sample.status |= knhv::kCpuMatrixSampleCollected;
    return sample;
}

Collection CollectMatrix(const Options& options) {
    Collection result;
    result.collection_limit = options.max_processors;
    const std::vector<LogicalProcessor> processors = EnumerateProcessors();
    if (processors.size() > (std::numeric_limits<std::uint32_t>::max)()) {
        result.expected_count = (std::numeric_limits<std::uint32_t>::max)();
    } else {
        result.expected_count = static_cast<std::uint32_t>(processors.size());
    }
    result.truncated = processors.size() > options.max_processors;

    GROUP_AFFINITY original{};
    result.affinity_saved =
        GetThreadGroupAffinity(GetCurrentThread(), &original) != FALSE;
    if (!result.affinity_saved) {
        result.affinity_error = GetLastError();
    }

    const std::size_t limit =
        std::min<std::size_t>(processors.size(), options.max_processors);
    result.samples.reserve(limit);
    for (std::size_t index = 0; index < limit; ++index) {
        const LogicalProcessor& processor = processors[index];
        knhv::CpuMatrixSample sample{};
        sample.size = sizeof(sample);
        sample.version = knhv::kCpuMatrixContractVersion;
        sample.logical_index = processor.index;
        sample.processor_group = processor.group;
        sample.processor_number = processor.number;
        if (!result.affinity_saved) {
            sample.status = knhv::kCpuMatrixSampleAffinityFailed;
            result.samples.push_back(sample);
            continue;
        }

        DWORD error = ERROR_SUCCESS;
        if (!PinCurrentThread(processor, error)) {
            sample.status = knhv::kCpuMatrixSampleAffinityFailed;
            result.affinity_error = error;
            result.samples.push_back(sample);
            if (!RestoreAffinity(original, result)) break;
            continue;
        }
        sample = CollectSample(processor);
        result.samples.push_back(sample);

        if (!RestoreAffinity(original, result)) break;
    }
    if (result.affinity_saved && !result.affinity_restored) {
        RestoreAffinity(original, result);
    }
    return result;
}

std::string BuildJson(const Collection& collection,
                      const knhv::CpuMatrixSummary& summary,
                      bool model_valid, bool uniform, const char* verdict,
                      const char* reason) {
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\":\"knhv-cpu-matrix-1\",\n"
           << "  \"tool\":\"KNHV_CpuMatrix\",\n"
           << "  \"created_at\":\"" << NowIso8601() << "\",\n"
           << "  \"verdict\":\"" << verdict << "\",\n"
           << "  \"reason\":\"" << JsonEscape(reason) << "\",\n"
           << "  \"read_only\":true,\n"
           << "  \"required_features\":\""
           << Hex(kRequiredFeatures) << "\",\n"
           << "  \"model_valid\":" << (model_valid ? "true" : "false")
           << ",\n"
           << "  \"uniform_required_features\":"
           << (uniform ? "true" : "false") << ",\n"
           << "  \"expected_count\":" << collection.expected_count << ",\n"
           << "  \"sample_count\":" << collection.samples.size() << ",\n"
           << "  \"collection_limit\":" << collection.collection_limit
           << ",\n"
           << "  \"truncated\":"
           << (collection.truncated ? "true" : "false") << ",\n"
           << "  \"affinity_saved\":"
           << (collection.affinity_saved ? "true" : "false") << ",\n"
           << "  \"affinity_restored\":"
           << (collection.affinity_restored ? "true" : "false") << ",\n"
           << "  \"affinity_error\":\""
           << Hex(collection.affinity_error) << "\",\n"
           << "  \"summary\":{\"state\":\"" << StateText(summary.state)
           << "\",\"flags\":\"" << Hex(summary.flags)
           << "\",\"valid_count\":" << summary.valid_count
           << ",\"invalid_count\":" << summary.invalid_count
           << ",\"feature_intersection\":\""
           << Hex(summary.feature_intersection)
           << "\",\"feature_union\":\"" << Hex(summary.feature_union)
           << "\",\"inconsistent_features\":\""
           << Hex(summary.inconsistent_features)
           << "\",\"common_max_basic_leaf\":\""
           << Hex(summary.common_max_basic_leaf)
           << "\",\"common_max_extended_leaf\":\""
           << Hex(summary.common_max_extended_leaf)
           << "\",\"common_physical_address_bits\":"
           << summary.common_physical_address_bits
           << ",\"common_linear_address_bits\":"
           << summary.common_linear_address_bits << "},\n"
           << "  \"privileged_controls\":{\"vmx_control_msrs\":\"unknown\","
           << "\"ept_vpid\":\"unknown\",\"iommu\":\"unknown\"},\n"
           << "  \"samples\":[";
    for (std::size_t index = 0; index < collection.samples.size(); ++index) {
        if (index != 0U) output << ',';
        const knhv::CpuMatrixSample& sample = collection.samples[index];
        output << "{\"index\":" << sample.logical_index
               << ",\"group\":" << sample.processor_group
               << ",\"number\":" << sample.processor_number
               << ",\"status\":\"" << Hex(sample.status)
               << "\",\"features\":\"" << Hex(sample.feature_flags)
               << "\",\"max_basic_leaf\":\""
               << Hex(sample.max_basic_leaf)
               << "\",\"max_extended_leaf\":\""
               << Hex(sample.max_extended_leaf)
               << "\",\"physical_address_bits\":"
               << sample.physical_address_bits
               << ",\"linear_address_bits\":"
               << sample.linear_address_bits
               << ",\"vendor\":[\"" << Hex(sample.vendor_ebx)
               << "\",\"" << Hex(sample.vendor_ecx) << "\",\""
               << Hex(sample.vendor_edx) << "\"],\"hypervisor_vendor\":[\""
               << Hex(sample.hypervisor_ebx) << "\",\""
               << Hex(sample.hypervisor_ecx) << "\",\""
               << Hex(sample.hypervisor_edx) << "\"],\"leaf1\":[\""
               << Hex(sample.leaf1_ecx) << "\",\"" << Hex(sample.leaf1_edx)
               << "\"],\"leaf7\":[\"" << Hex(sample.leaf7_ebx) << "\",\""
               << Hex(sample.leaf7_ecx) << "\",\"" << Hex(sample.leaf7_edx)
               << "\"],\"extended_leaf7_edx\":\""
               << Hex(sample.extended_leaf7_edx)
               << "\",\"extended_leaf8_eax\":\""
               << Hex(sample.extended_leaf8_eax) << "\"}";
    }
    output << "],\n"
           << "  \"actions\":[\"CPUID and temporary thread affinity only\","
           << "\"no VMXON, MSR access, driver load, BCD change, or DMA\"]\n"
           << "}\n";
    return output.str();
}

bool WriteOutput(const fs::path& path, const std::string& text) {
    if (path.empty()) {
        std::cout << text;
        return true;
    }
    std::error_code error;
    const fs::path parent = path.parent_path();
    if (!parent.empty()) fs::create_directories(parent, error);
    if (error) return false;
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(text.data(), static_cast<std::streamsize>(text.size()));
    return file.good();
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

    const Collection collection = CollectMatrix(options);
    knhv::CpuMatrixSummary summary{};
    const bool summary_built = knhv::BuildCpuMatrixSummary(
        collection.samples.empty() ? nullptr : collection.samples.data(),
        static_cast<std::uint32_t>(collection.samples.size()),
        collection.expected_count, &summary);
    const bool model_valid =
        summary_built && knhv::IsCpuMatrixSummaryValid(&summary);
    const bool uniform =
        model_valid && knhv::IsCpuMatrixUniform(&summary, kRequiredFeatures) &&
        collection.affinity_restored && !collection.truncated;
    const char* verdict = model_valid && uniform ? "pass" : "blocked";
    const char* reason = !model_valid
                             ? "capability matrix is structurally invalid"
                         : uniform
                             ? "all sampled processors are uniform"
                             : "processor matrix is incomplete or lacks required features";
    const std::string json = BuildJson(collection, summary, model_valid,
                                       uniform, verdict, reason);
    if (!WriteOutput(options.output, json)) return kExitInvalid;
    if (!model_valid) return kExitInvalid;
    return uniform ? kExitSuccess : kExitBlocked;
}
