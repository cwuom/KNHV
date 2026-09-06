#include "test_support.h"

#include "knhv_target_evidence_signature.h"

#include <array>
#include <string>

namespace knhv_tests {
namespace {

knhv::TargetEvidenceSignatureRequest MakeRequest(knhv::u32 flags = 0U) {
    knhv::TargetEvidenceSignatureRequest request{};
    request.size = sizeof(request);
    request.version = knhv::kTargetEvidenceSignatureContractVersion;
    request.flags = flags;
    return request;
}

knhv::TargetEvidenceSignatureResult MakeResult(
    knhv::TargetEvidenceSignatureStatus status,
    knhv::u32 wintrust_status = 0U, knhv::u32 result_flags = 0U) {
    knhv::TargetEvidenceSignatureResult result{};
    result.size = sizeof(result);
    result.version = knhv::kTargetEvidenceSignatureContractVersion;
    result.status = static_cast<knhv::u32>(status);
    result.wintrust_status = wintrust_status;
    result.result_flags = result_flags;
    return result;
}

}  // namespace

void RunTargetEvidenceSignatureContract(TestState& state) {
    Check(state, "signature request ABI is fixed",
          sizeof(knhv::TargetEvidenceSignatureRequest) == 16U &&
              sizeof(knhv::TargetEvidenceSignatureResult) == 24U);

    const auto valid_request = MakeRequest();
    Check(state, "signature request accepts the current version",
          knhv::IsTargetEvidenceSignatureRequestValid(&valid_request));

    auto unknown_flags = valid_request;
    unknown_flags.flags = 1U << 31;
    Check(state, "signature request rejects unknown flags",
          !knhv::IsTargetEvidenceSignatureRequestValid(&unknown_flags));

    auto reserved_request = valid_request;
    reserved_request.reserved = 1U;
    Check(state, "signature request rejects reserved bits",
          !knhv::IsTargetEvidenceSignatureRequestValid(&reserved_request));

    auto old_request = valid_request;
    old_request.version = 0U;
    Check(state, "signature request rejects an unsupported version",
          !knhv::IsTargetEvidenceSignatureRequestValid(&old_request));

    auto short_request = valid_request;
    short_request.size = sizeof(short_request) - 1U;
    Check(state, "signature request rejects a truncated buffer",
          !knhv::IsTargetEvidenceSignatureRequestValid(&short_request));

    const auto trusted = MakeResult(
        knhv::TargetEvidenceSignatureStatus::Trusted);
    Check(state, "trusted signature result has a zero trust status",
          knhv::IsTargetEvidenceSignatureResultValid(&trusted));

    auto forged_trusted = trusted;
    forged_trusted.wintrust_status = 1U;
    Check(state, "trusted result rejects a nonzero trust status",
          !knhv::IsTargetEvidenceSignatureResultValid(&forged_trusted));

    const auto not_signed = MakeResult(
        knhv::TargetEvidenceSignatureStatus::NotSigned, 1U);
    Check(state, "not signed result carries a trust failure",
          knhv::IsTargetEvidenceSignatureResultValid(&not_signed));

    auto forged_not_signed = not_signed;
    forged_not_signed.wintrust_status = 0U;
    Check(state, "not signed result rejects a zero trust status",
          !knhv::IsTargetEvidenceSignatureResultValid(&forged_not_signed));

    const auto private_root = MakeResult(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot, 1U,
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted);
    Check(state, "private test root requires explicit acceptance",
          knhv::IsTargetEvidenceSignatureResultValid(&private_root));

    auto private_root_without_flag = private_root;
    private_root_without_flag.result_flags = 0U;
    Check(state, "private test root result requires the acceptance flag",
          !knhv::IsTargetEvidenceSignatureResultValid(
              &private_root_without_flag));

    auto unknown_result = trusted;
    unknown_result.status = 0xFFFFFFFFU;
    Check(state, "signature result rejects an unknown status",
          !knhv::IsTargetEvidenceSignatureResultValid(&unknown_result));

    auto reserved_result = trusted;
    reserved_result.reserved = 1U;
    Check(state, "signature result rejects reserved bits",
          !knhv::IsTargetEvidenceSignatureResultValid(&reserved_result));

    knhv::TargetEvidenceSignatureResult result{};
    const auto missing_path =
        L"Z:\\knhv-evidence-signature\\missing-image-9c6c.bin";
    const auto missing_status = knhv::VerifyTargetEvidenceFileSignature(
        missing_path, &valid_request, &result);
    Check(state, "missing signature input is blocked",
          missing_status == knhv::TargetEvidenceSignatureStatus::FileNotFound &&
              result.status == static_cast<knhv::u32>(
                                    knhv::TargetEvidenceSignatureStatus::
                                        FileNotFound) &&
              knhv::IsTargetEvidenceSignatureResultValid(&result));

    result = {};
    const auto null_path_status = knhv::VerifyTargetEvidenceFileSignature(
        nullptr, &valid_request, &result);
    Check(state, "null signature path is rejected",
          null_path_status ==
              knhv::TargetEvidenceSignatureStatus::InvalidArgument &&
              knhv::IsTargetEvidenceSignatureResultValid(&result));

    std::wstring overlong_path(
        static_cast<std::size_t>(knhv::kTargetEvidenceSignatureMaxPath) + 1U,
        L'x');
    result = {};
    const auto overlong_status = knhv::VerifyTargetEvidenceFileSignature(
        overlong_path.c_str(), &valid_request, &result);
    Check(state, "overlong signature path is rejected",
          overlong_status ==
              knhv::TargetEvidenceSignatureStatus::InvalidArgument &&
              knhv::IsTargetEvidenceSignatureResultValid(&result));

    Check(state, "null signature result is rejected",
          knhv::VerifyTargetEvidenceFileSignature(
              missing_path, &valid_request, nullptr) ==
              knhv::TargetEvidenceSignatureStatus::InvalidArgument);

    const std::array<knhv::TargetEvidenceSignatureStatus, 7> statuses = {
        knhv::TargetEvidenceSignatureStatus::Trusted,
        knhv::TargetEvidenceSignatureStatus::InvalidArgument,
        knhv::TargetEvidenceSignatureStatus::FileNotFound,
        knhv::TargetEvidenceSignatureStatus::NotSigned,
        knhv::TargetEvidenceSignatureStatus::Untrusted,
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot,
        knhv::TargetEvidenceSignatureStatus::VerificationUnavailable};
    bool status_texts_present = true;
    for (const auto status : statuses) {
        status_texts_present =
            status_texts_present &&
            std::string(knhv::TargetEvidenceSignatureStatusText(status)) !=
                "unknown";
    }
    Check(state, "signature statuses have stable text", status_texts_present);
}

}  // namespace knhv_tests
