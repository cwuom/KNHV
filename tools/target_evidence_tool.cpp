#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "knhv_target_evidence_codec.h"
#include "knhv_target_evidence_signature.h"
#include "knhv_target_evidence_writer.h"

namespace {

namespace fs = std::filesystem;

constexpr int kExitSuccess = 0;
constexpr int kExitUsage = 2;
constexpr int kExitBlocked = 10;
constexpr int kExitInvalid = 11;
constexpr int kExitIo = 12;
constexpr knhv::u32 kSyntheticPrivateRootMarker = 1U;

enum class Operation : std::uint32_t {
    None = 0,
    EmitSynthetic = 1,
    Validate = 2,
    Gate = 3,
    VerifySignature = 4,
};

struct Options {
    Operation operation = Operation::None;
    fs::path input;
    fs::path output;
    knhv::TargetEvidenceProfile profile =
        knhv::TargetEvidenceProfile::Unknown;
    knhv::TargetEvidenceStage stage = knhv::TargetEvidenceStage::Inventory;
    std::uint64_t expected_generation = 0U;
    bool profile_set = false;
    bool stage_set = false;
    bool generation_set = false;
    bool allow_test_root = false;
    bool help = false;
};

void PrintUsage() {
    std::cout
        << "KNHV_EvidenceTool --emit-synthetic path [--out report.json]\n"
        << "KNHV_EvidenceTool --validate path [--out report.json]\n"
        << "KNHV_EvidenceTool --gate path --profile profile --stage stage"
           " [--expected-generation value] [--out report.json]\n"
        << "KNHV_EvidenceTool --verify-signature path"
           " [--allow-test-root] [--out report.json]\n"
        << "  profiles: native-intel-l0, whp-managed, external-l0,"
           " synthetic-lab\n"
        << "  stages: inventory, preflight, capability, boot, nested,"
           " device, performance, reliability, release\n"
        << "  emit-synthetic creates laboratory evidence only; it never"
           " asserts hardware ownership\n"
        << "  verify-signature uses WinVerifyTrust with no online revocation"
           " check\n";
}

bool TakePath(int& index, int argc, wchar_t** argv, fs::path& path) {
    if (index + 1 >= argc) return false;
    const std::wstring_view candidate(argv[index + 1]);
    if (candidate.empty() ||
        (candidate.size() >= 2U && candidate[0] == L'-' &&
         candidate[1] == L'-')) {
        return false;
    }
    path = fs::path(argv[++index]);
    return !path.empty();
}

bool ParseUnsigned(std::wstring_view text, std::uint64_t& value) {
    if (text.empty() || text.front() == L'-' || text.front() == L'+') {
        return false;
    }
    const std::wstring copy(text);
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::wcstoull(copy.c_str(), &end, 0);
    if (errno == ERANGE || end == copy.c_str() || *end != L'\0') {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool ParseProfile(std::wstring_view text,
                  knhv::TargetEvidenceProfile& profile) {
    if (text == L"native-intel-l0") {
        profile = knhv::TargetEvidenceProfile::NativeIntelL0;
    } else if (text == L"whp-managed") {
        profile = knhv::TargetEvidenceProfile::WhpManaged;
    } else if (text == L"external-l0") {
        profile = knhv::TargetEvidenceProfile::ExternalL0;
    } else if (text == L"synthetic-lab") {
        profile = knhv::TargetEvidenceProfile::SyntheticLab;
    } else {
        return false;
    }
    return true;
}

bool ParseStage(std::wstring_view text, knhv::TargetEvidenceStage& stage) {
    const std::array<std::wstring_view, 9> names = {
        L"inventory", L"preflight", L"capability", L"boot", L"nested",
        L"device", L"performance", L"reliability", L"release"};
    for (std::size_t index = 0U; index < names.size(); ++index) {
        if (text == names[index]) {
            stage = static_cast<knhv::TargetEvidenceStage>(index);
            return true;
        }
    }
    return false;
}

bool SetOperation(Options& options, Operation operation, const fs::path& input,
                  std::string& error) {
    if (options.operation != Operation::None) {
        error = "only one operation may be selected";
        return false;
    }
    options.operation = operation;
    options.input = input;
    return true;
}

bool ParseOptions(int argc, wchar_t** argv, Options& options,
                  std::string& error) {
    for (int index = 1; index < argc; ++index) {
        const std::wstring_view argument(argv[index]);
        if (argument == L"--help" || argument == L"-h") {
            options.help = true;
            return true;
        }
        if (argument == L"--emit-synthetic") {
            fs::path path;
            if (!TakePath(index, argc, argv, path) ||
                !SetOperation(options, Operation::EmitSynthetic, path,
                               error)) {
                if (error.empty()) error = "--emit-synthetic needs a path";
                return false;
            }
        } else if (argument == L"--validate") {
            fs::path path;
            if (!TakePath(index, argc, argv, path) ||
                !SetOperation(options, Operation::Validate, path, error)) {
                if (error.empty()) error = "--validate needs a path";
                return false;
            }
        } else if (argument == L"--gate") {
            fs::path path;
            if (!TakePath(index, argc, argv, path) ||
                !SetOperation(options, Operation::Gate, path, error)) {
                if (error.empty()) error = "--gate needs a path";
                return false;
            }
        } else if (argument == L"--verify-signature") {
            fs::path path;
            if (!TakePath(index, argc, argv, path) ||
                !SetOperation(options, Operation::VerifySignature, path,
                               error)) {
                if (error.empty()) error = "--verify-signature needs a path";
                return false;
            }
        } else if (argument == L"--profile") {
            if (index + 1 >= argc ||
                !ParseProfile(argv[++index], options.profile)) {
                error = "--profile is unknown";
                return false;
            }
            options.profile_set = true;
        } else if (argument == L"--stage") {
            if (index + 1 >= argc ||
                !ParseStage(argv[++index], options.stage)) {
                error = "--stage is unknown";
                return false;
            }
            options.stage_set = true;
        } else if (argument == L"--expected-generation") {
            if (index + 1 >= argc ||
                !ParseUnsigned(argv[++index], options.expected_generation)) {
                error = "--expected-generation is invalid";
                return false;
            }
            if (options.expected_generation == 0U) {
                error = "--expected-generation must be nonzero";
                return false;
            }
            options.generation_set = true;
        } else if (argument == L"--out") {
            if (!TakePath(index, argc, argv, options.output)) {
                error = "--out needs a path";
                return false;
            }
        } else if (argument == L"--allow-test-root") {
            options.allow_test_root = true;
        } else {
            error = "unknown option";
            return false;
        }
    }

    if (options.operation == Operation::None) {
        error = "an operation is required";
        return false;
    }
    if (options.operation == Operation::Gate &&
        options.profile == knhv::TargetEvidenceProfile::Unknown) {
        error = "--gate requires --profile";
        return false;
    }
    if (options.operation == Operation::Gate && !options.stage_set) {
        error = "--gate requires --stage";
        return false;
    }
    if (options.operation != Operation::Gate &&
        (options.profile_set || options.stage_set || options.generation_set)) {
        error = "profile, stage, and generation apply only to --gate";
        return false;
    }
    if (options.operation != Operation::VerifySignature &&
        options.allow_test_root) {
        error = "--allow-test-root applies only to --verify-signature";
        return false;
    }
    return true;
}

void FillDigest(knhv::u8* digest, knhv::u8 seed) {
    for (knhv::u32 index = 0U; index < 32U; ++index) {
        digest[index] = static_cast<knhv::u8>(seed + index);
    }
}

knhv::TargetEvidenceManifest MakeSyntheticManifest() {
    knhv::TargetEvidenceManifest manifest{};
    manifest.size = sizeof(manifest);
    manifest.version = knhv::kTargetEvidenceContractVersion;
    manifest.profile = static_cast<knhv::u32>(
        knhv::TargetEvidenceProfile::SyntheticLab);
    manifest.stage = static_cast<knhv::u32>(
        knhv::TargetEvidenceStage::Release);
    manifest.verdict = static_cast<knhv::u32>(
        knhv::TargetEvidenceVerdict::Pass);
    manifest.flags = knhv::RequiredTargetEvidenceFlags(
        knhv::TargetEvidenceProfile::SyntheticLab,
        knhv::TargetEvidenceStage::Release);
    manifest.owner_kind = static_cast<knhv::u32>(
        knhv::HvOwnerKindV2::SyntheticLab);
    manifest.owner_state = static_cast<knhv::u32>(
        knhv::HvProviderStateV2::Active);
    manifest.cpu_count = 1U;
    manifest.cpu_valid_count = 1U;
    manifest.artifact_count = 1U;
    manifest.generation = 1U;
    manifest.started_tsc = 100U;
    manifest.ended_tsc = 200U;
    FillDigest(manifest.build_id, 1U);
    FillDigest(manifest.artifact_hash, 2U);
    FillDigest(manifest.capability_hash, 3U);
    FillDigest(manifest.manifest_hash, 4U);
    return manifest;
}

bool ReadBytes(const fs::path& path, std::vector<knhv::u8>& bytes,
               std::string& error) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        error = "input cannot be opened";
        return false;
    }
    const std::streamoff end = file.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) >
                       knhv::kTargetEvidenceWireMaxSize) {
        error = "input exceeds the bounded wire size";
        return false;
    }
    file.seekg(0, std::ios::beg);
    if (!file) {
        error = "input cannot be rewound";
        return false;
    }
    bytes.resize(static_cast<std::size_t>(end));
    if (!bytes.empty()) {
        file.read(reinterpret_cast<char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    if (file.gcount() != static_cast<std::streamsize>(bytes.size())) {
        error = "input read failed";
        bytes.clear();
        return false;
    }
    return true;
}

bool WriteBytes(const fs::path& path, const std::vector<knhv::u8>& bytes,
                std::string& error) {
    if (path.empty()) {
        error = "output path is empty";
        return false;
    }
    std::error_code filesystem_error;
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path(), filesystem_error);
        if (filesystem_error) {
            error = "output directory cannot be created";
            return false;
        }
    }
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        error = "output cannot be opened";
        return false;
    }
    if (!bytes.empty()) {
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    if (!file.good()) {
        error = "output write failed";
        return false;
    }
    return true;
}

std::string JsonEscape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8U);
    for (const unsigned char character : value) {
        switch (character) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result.push_back(static_cast<char>(character)); break;
        }
    }
    return result;
}

const char* HvStatusText(knhv::HvStatus status) {
    switch (status) {
        case knhv::HvStatus::Success: return "success";
        case knhv::HvStatus::CapabilityMismatch: return "capability-mismatch";
        case knhv::HvStatus::HardwareOwnerConflict:
            return "hardware-owner-conflict";
        case knhv::HvStatus::NestedUnavailable: return "nested-unavailable";
        case knhv::HvStatus::BootHandoffFailed: return "boot-handoff-failed";
        case knhv::HvStatus::RecoveryRequired: return "recovery-required";
        case knhv::HvStatus::IncompatibleProvider:
            return "incompatible-provider";
        case knhv::HvStatus::Busy: return "busy";
        case knhv::HvStatus::InvalidParameter: return "invalid-parameter";
        default: return "other";
    }
}

std::string BuildJson(const char* operation, const char* status,
                      std::string_view reason, const fs::path& path,
                      const knhv::TargetEvidenceManifest* manifest,
                      const knhv::TargetEvidenceGateResult* gate,
                      bool digest_verified, bool synthetic) {
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\":\"knhv-target-evidence-tool-1\",\n"
           << "  \"operation\":\"" << operation << "\",\n"
           << "  \"status\":\"" << status << "\",\n"
           << "  \"reason\":\"" << JsonEscape(reason) << "\",\n"
           << "  \"path\":\"" << JsonEscape(path.generic_string())
           << "\",\n"
           << "  \"digest_verified\":"
           << (digest_verified ? "true" : "false") << ",\n"
           << "  \"synthetic_fixture\":"
           << (synthetic ? "true" : "false") << ",\n"
           << "  \"hardware_execution\":false";
    if (manifest != nullptr) {
        output << ",\n  \"manifest\":{\n"
               << "    \"profile\":\""
               << knhv::TargetEvidenceProfileText(
                      static_cast<knhv::TargetEvidenceProfile>(
                          manifest->profile))
               << "\",\n"
               << "    \"stage\":\""
               << knhv::TargetEvidenceStageText(
                      static_cast<knhv::TargetEvidenceStage>(manifest->stage))
               << "\",\n"
               << "    \"verdict\":\""
               << knhv::TargetEvidenceVerdictText(
                      static_cast<knhv::TargetEvidenceVerdict>(
                          manifest->verdict))
               << "\",\n"
               << "    \"flags\":\"0x" << std::hex << manifest->flags
               << std::dec << "\",\n"
               << "    \"generation\":" << manifest->generation << "\n"
               << "  }";
    }
    if (gate != nullptr) {
        output << ",\n  \"gate\":{\n"
               << "    \"status_code\":"
               << static_cast<std::uint32_t>(gate->status) << ",\n"
               << "    \"status\":\"" << HvStatusText(gate->status)
               << "\",\n"
               << "    \"reason_code\":" << gate->reason << ",\n"
               << "    \"reason\":\""
               << knhv::TargetEvidenceReasonText(
                      static_cast<knhv::TargetEvidenceReason>(gate->reason))
               << "\",\n"
               << "    \"missing_flags\":\"0x" << std::hex
               << gate->missing_flags << "\",\n"
               << "    \"observed_flags\":\"0x" << gate->observed_flags
               << std::dec << "\",\n"
               << "    \"generation\":" << gate->generation << "\n"
               << "  }";
    }
    output << "\n}\n";
    return output.str();
}

std::string HexU32(std::uint32_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << value;
    return output.str();
}

std::string BuildSignatureJson(
    const fs::path& path, const knhv::TargetEvidenceSignatureResult& result,
    bool allow_test_root) {
    const auto signature_status =
        static_cast<knhv::TargetEvidenceSignatureStatus>(result.status);
    const bool passed =
        signature_status == knhv::TargetEvidenceSignatureStatus::Trusted ||
        signature_status ==
            knhv::TargetEvidenceSignatureStatus::PrivateTestRoot;
    const bool blocked =
        signature_status == knhv::TargetEvidenceSignatureStatus::NotSigned ||
        signature_status == knhv::TargetEvidenceSignatureStatus::Untrusted;
    const bool private_root_accepted =
        (result.result_flags &
         knhv::kTargetEvidenceSignatureResultPrivateRootAccepted) != 0U;
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\":\"knhv-target-evidence-tool-1\",\n"
           << "  \"operation\":\"verify-signature\",\n"
           << "  \"status\":\""
           << (passed ? "pass" : (blocked ? "blocked" : "fail"))
           << "\",\n"
           << "  \"reason\":\""
           << knhv::TargetEvidenceSignatureStatusText(signature_status)
           << "\",\n"
           << "  \"path\":\"" << JsonEscape(path.generic_string())
           << "\",\n"
           << "  \"hardware_execution\":false,\n"
           << "  \"revocation_checks\":\"none\",\n"
           << "  \"cache_only_url_retrieval\":true,\n"
           << "  \"certificate_store_modified\":false,\n"
           << "  \"verifier\":\"WinVerifyTrust\",\n"
           << "  \"signature\":{\n"
           << "    \"status_code\":" << result.status << ",\n"
           << "    \"status\":\""
           << knhv::TargetEvidenceSignatureStatusText(signature_status)
           << "\",\n"
           << "    \"wintrust_status\":\""
           << HexU32(result.wintrust_status) << "\",\n"
           << "    \"allow_private_test_root\":"
           << (allow_test_root ? "true" : "false") << ",\n"
           << "    \"private_test_root_accepted\":"
           << (private_root_accepted ? "true" : "false") << "\n"
           << "  }\n"
           << "}\n";
    return output.str();
}

bool WriteReport(const fs::path& path, const std::string& text,
                 std::string& error) {
    if (path.empty()) {
        std::cout << text;
        return true;
    }
    std::error_code filesystem_error;
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path(), filesystem_error);
        if (filesystem_error) {
            error = "report directory cannot be created";
            return false;
        }
    }
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        error = "report cannot be opened";
        return false;
    }
    file << text;
    if (!file.good()) {
        error = "report write failed";
        return false;
    }
    return true;
}

int RunEmit(const Options& options) {
    const knhv::TargetEvidenceManifest candidate = MakeSyntheticManifest();
    knhv::TargetEvidenceSignatureResult signature{};
    signature.size = sizeof(signature);
    signature.version = knhv::kTargetEvidenceSignatureContractVersion;
    signature.status = static_cast<knhv::u32>(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot);
    signature.wintrust_status = kSyntheticPrivateRootMarker;
    signature.result_flags =
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted;

    knhv::TargetEvidenceManifestWriteRequest write_request{};
    write_request.size = sizeof(write_request);
    write_request.version = knhv::kTargetEvidenceWriterContractVersion;
    write_request.flags =
        knhv::kTargetEvidenceWriterFlagAllowSynthetic |
        knhv::kTargetEvidenceWriterFlagAllowPrivateTestRoot |
        knhv::kTargetEvidenceWriterFlagSourceCleanObserved |
        knhv::kTargetEvidenceWriterFlagCommitSignature;
    write_request.candidate = candidate;
    write_request.signature = signature;
    knhv::TargetEvidenceManifestWriteResult write_result{};
    if (!knhv::BuildTargetEvidenceManifest(&write_request, &write_result) ||
        write_result.status != static_cast<knhv::u32>(
                                    knhv::TargetEvidenceWriterStatus::Success) ||
        !knhv::IsTargetEvidenceManifestWriteResultValid(&write_result)) {
        std::cerr << "manifest writer rejected synthetic evidence: "
                  << knhv::TargetEvidenceWriterStatusText(
                         static_cast<knhv::TargetEvidenceWriterStatus>(
                             write_result.status))
                  << '\n';
        return kExitInvalid;
    }
    const knhv::TargetEvidenceManifest& manifest = write_result.manifest;
    std::array<knhv::u8, knhv::kTargetEvidenceWireEnvelopeSize> encoded{};
    knhv::u32 written = 0U;
    const knhv::TargetEvidenceCodecStatus status =
        knhv::EncodeTargetEvidencePackage(
            &manifest, encoded.data(), static_cast<knhv::u32>(encoded.size()),
            &written);
    if (status != knhv::TargetEvidenceCodecStatus::Success) {
        std::cerr << "encode failed: "
                  << knhv::TargetEvidenceCodecStatusText(status) << '\n';
        return kExitInvalid;
    }
    if (written != encoded.size()) {
        std::cerr << "encode returned an unexpected envelope size\n";
        return kExitInvalid;
    }
    const std::vector<knhv::u8> bytes(encoded.begin(),
                                      encoded.begin() + written);
    std::string error;
    if (!WriteBytes(options.input, bytes, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    const std::string report = BuildJson(
        "emit-synthetic", "pass", "synthetic package emitted", options.input,
        &manifest, nullptr, true, true);
    if (!WriteReport(options.output, report, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    return kExitSuccess;
}

int RunValidate(const Options& options) {
    std::vector<knhv::u8> bytes;
    std::string error;
    if (!ReadBytes(options.input, bytes, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    knhv::TargetEvidenceManifest manifest{};
    const knhv::TargetEvidenceCodecStatus status =
        knhv::DecodeTargetEvidencePackage(
            bytes.data(), static_cast<knhv::u32>(bytes.size()), &manifest);
    const bool valid = status == knhv::TargetEvidenceCodecStatus::Success;
    const bool synthetic =
        valid && manifest.profile == static_cast<knhv::u32>(
                          knhv::TargetEvidenceProfile::SyntheticLab);
    const std::string report = BuildJson(
        "validate", valid ? "pass" : "fail",
        knhv::TargetEvidenceCodecStatusText(status), options.input,
        valid ? &manifest : nullptr, nullptr, valid, synthetic);
    if (!WriteReport(options.output, report, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    return valid ? kExitSuccess : kExitInvalid;
}

int RunGate(const Options& options) {
    std::vector<knhv::u8> bytes;
    std::string error;
    if (!ReadBytes(options.input, bytes, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    knhv::TargetEvidenceManifest manifest{};
    const knhv::TargetEvidenceCodecStatus decode_status =
        knhv::DecodeTargetEvidencePackage(
            bytes.data(), static_cast<knhv::u32>(bytes.size()), &manifest);
    if (decode_status != knhv::TargetEvidenceCodecStatus::Success) {
        const std::string report = BuildJson(
            "gate", "fail", knhv::TargetEvidenceCodecStatusText(decode_status),
            options.input, nullptr, nullptr, false, false);
        if (!WriteReport(options.output, report, error)) {
            std::cerr << error << '\n';
            return kExitIo;
        }
        return kExitInvalid;
    }

    knhv::TargetEvidenceGateRequest request{};
    request.size = sizeof(request);
    request.version = knhv::kTargetEvidenceContractVersion;
    request.profile = static_cast<knhv::u32>(options.profile);
    request.minimum_stage = static_cast<knhv::u32>(options.stage);
    request.expected_generation =
        options.generation_set ? options.expected_generation : 0U;
    knhv::TargetEvidenceGateResult result{};
    const bool evaluated = knhv::EvaluateTargetEvidenceGate(
        &manifest, &request, &result);
    if (!evaluated) {
        error = "gate request or manifest is invalid";
        const std::string report = BuildJson(
            "gate", "fail", error, options.input, &manifest, nullptr, true,
            false);
        if (!WriteReport(options.output, report, error)) {
            std::cerr << error << '\n';
            return kExitIo;
        }
        return kExitInvalid;
    }
    const bool passed = result.status == knhv::HvStatus::Success;
    const std::string report = BuildJson(
        "gate", passed ? "pass" : "blocked",
        knhv::TargetEvidenceReasonText(
            static_cast<knhv::TargetEvidenceReason>(result.reason)),
        options.input, &manifest, &result, true,
        manifest.profile == static_cast<knhv::u32>(
                              knhv::TargetEvidenceProfile::SyntheticLab));
    if (!WriteReport(options.output, report, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    return passed ? kExitSuccess : kExitBlocked;
}

int RunVerifySignature(const Options& options) {
    knhv::TargetEvidenceSignatureRequest request{};
    request.size = sizeof(request);
    request.version = knhv::kTargetEvidenceSignatureContractVersion;
    request.flags = options.allow_test_root
                        ? knhv::kTargetEvidenceSignatureFlagAllowPrivateTestRoot
                        : 0U;
    knhv::TargetEvidenceSignatureResult result{};
    const std::wstring path = options.input.wstring();
    const knhv::TargetEvidenceSignatureStatus status =
        knhv::VerifyTargetEvidenceFileSignature(path.c_str(), &request,
                                                &result);
    std::string error;
    if (!knhv::IsTargetEvidenceSignatureResultValid(&result)) {
        std::cerr << "signature verifier returned an invalid result\n";
        return kExitInvalid;
    }
    const std::string report =
        BuildSignatureJson(options.input, result, options.allow_test_root);
    if (!WriteReport(options.output, report, error)) {
        std::cerr << error << '\n';
        return kExitIo;
    }
    switch (status) {
        case knhv::TargetEvidenceSignatureStatus::Trusted:
        case knhv::TargetEvidenceSignatureStatus::PrivateTestRoot:
            return kExitSuccess;
        case knhv::TargetEvidenceSignatureStatus::NotSigned:
        case knhv::TargetEvidenceSignatureStatus::Untrusted:
            return kExitBlocked;
        case knhv::TargetEvidenceSignatureStatus::FileNotFound:
            return kExitIo;
        case knhv::TargetEvidenceSignatureStatus::VerificationUnavailable:
            return kExitInvalid;
        case knhv::TargetEvidenceSignatureStatus::InvalidArgument:
        default:
            return kExitUsage;
    }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    Options options;
    std::string error;
    if (!ParseOptions(argc, argv, options, error)) {
        std::cerr << "argument error: " << error << '\n';
        PrintUsage();
        return kExitUsage;
    }
    if (options.help) {
        PrintUsage();
        return kExitSuccess;
    }
    switch (options.operation) {
        case Operation::EmitSynthetic: return RunEmit(options);
        case Operation::Validate: return RunValidate(options);
        case Operation::Gate: return RunGate(options);
        case Operation::VerifySignature: return RunVerifySignature(options);
        default: return kExitUsage;
    }
}
