#include "test_support.h"

#include <cstdint>

#include "knhv_target_evidence.h"

namespace knhv_tests {
namespace {

void FillDigest(std::uint8_t (&digest)[32], std::uint8_t value) {
    for (std::uint8_t& byte : digest) byte = value;
}

knhv::TargetEvidenceManifest MakeManifest(
    knhv::TargetEvidenceProfile profile =
        knhv::TargetEvidenceProfile::NativeIntelL0,
    knhv::TargetEvidenceStage stage = knhv::TargetEvidenceStage::Release,
    knhv::TargetEvidenceVerdict verdict =
        knhv::TargetEvidenceVerdict::Pass) {
    knhv::TargetEvidenceManifest manifest = {};
    manifest.size = sizeof(manifest);
    manifest.version = knhv::kTargetEvidenceContractVersion;
    manifest.profile = static_cast<std::uint32_t>(profile);
    manifest.stage = static_cast<std::uint32_t>(stage);
    manifest.verdict = static_cast<std::uint32_t>(verdict);
    manifest.flags = knhv::RequiredTargetEvidenceFlags(profile, stage);
    switch (profile) {
        case knhv::TargetEvidenceProfile::NativeIntelL0:
            manifest.owner_kind = static_cast<std::uint32_t>(
                knhv::HvOwnerKindV2::KnhvBootL0);
            manifest.owner_state = static_cast<std::uint32_t>(
                knhv::HvProviderStateV2::Active);
            break;
        case knhv::TargetEvidenceProfile::WhpManaged:
            manifest.owner_kind = static_cast<std::uint32_t>(
                knhv::HvOwnerKindV2::WhpManaged);
            manifest.owner_state = static_cast<std::uint32_t>(
                knhv::HvProviderStateV2::Available);
            break;
        case knhv::TargetEvidenceProfile::ExternalL0:
            manifest.owner_kind = static_cast<std::uint32_t>(
                knhv::HvOwnerKindV2::ExternalL0);
            manifest.owner_state = static_cast<std::uint32_t>(
                knhv::HvProviderStateV2::Conflict);
            break;
        case knhv::TargetEvidenceProfile::SyntheticLab:
            manifest.owner_kind = static_cast<std::uint32_t>(
                knhv::HvOwnerKindV2::SyntheticLab);
            manifest.owner_state = static_cast<std::uint32_t>(
                knhv::HvProviderStateV2::Available);
            break;
        default:
            break;
    }
    manifest.cpu_count = 8;
    manifest.cpu_valid_count = 8;
    manifest.artifact_count = 12;
    manifest.generation = 9;
    manifest.started_tsc = 100;
    manifest.ended_tsc = 200;
    FillDigest(manifest.machine_id, 1);
    FillDigest(manifest.build_id, 2);
    FillDigest(manifest.artifact_hash, 3);
    FillDigest(manifest.capability_hash, 4);
    FillDigest(manifest.manifest_hash, 5);
    return manifest;
}

knhv::TargetEvidenceGateRequest MakeRequest(
    knhv::TargetEvidenceProfile profile =
        knhv::TargetEvidenceProfile::NativeIntelL0,
    knhv::TargetEvidenceStage stage = knhv::TargetEvidenceStage::Release) {
    knhv::TargetEvidenceGateRequest request = {};
    request.size = sizeof(request);
    request.version = knhv::kTargetEvidenceContractVersion;
    request.profile = static_cast<std::uint32_t>(profile);
    request.minimum_stage = static_cast<std::uint32_t>(stage);
    request.expected_generation = 9;
    return request;
}

void CheckManifestValidation(TestState& state) {
    auto manifest = MakeManifest();
    Check(state, "target evidence manifest validates with release proof",
          knhv::IsTargetEvidenceManifestValid(&manifest));
    Check(state, "target evidence required flags grow by stage",
          knhv::RequiredTargetEvidenceFlags(
              knhv::TargetEvidenceProfile::NativeIntelL0,
              knhv::TargetEvidenceStage::Preflight) == 0U &&
              (knhv::RequiredTargetEvidenceFlags(
                   knhv::TargetEvidenceProfile::NativeIntelL0,
                   knhv::TargetEvidenceStage::Capability) &
               knhv::kTargetEvidenceFlagCapabilityComplete) != 0U &&
              (knhv::RequiredTargetEvidenceFlags(
                   knhv::TargetEvidenceProfile::NativeIntelL0,
                   knhv::TargetEvidenceStage::Release) &
               knhv::kTargetEvidenceFlagSignatureVerified) != 0U);
    auto bad_hash = manifest;
    FillDigest(bad_hash.artifact_hash, 0);
    Check(state, "target evidence rejects verified artifacts without a hash",
          !knhv::IsTargetEvidenceManifestValid(&bad_hash));
    auto bad_counts = manifest;
    bad_counts.cpu_valid_count = bad_counts.cpu_count + 1U;
    Check(state, "target evidence rejects a CPU count beyond the sample set",
          !knhv::IsTargetEvidenceManifestValid(&bad_counts));
    auto bad_owner = manifest;
    bad_owner.owner_kind = static_cast<std::uint32_t>(
        knhv::HvOwnerKindV2::ExternalL0);
    Check(state, "target evidence rejects a profile and owner mismatch",
          !knhv::IsTargetEvidenceManifestValid(&bad_owner));
}

void CheckGateDecisions(TestState& state) {
    const auto manifest = MakeManifest();
    const auto request = MakeRequest();
    knhv::TargetEvidenceGateResult result = {};
    Check(state, "target evidence gate accepts complete release proof",
          knhv::IsTargetEvidenceGateRequestValid(&request) &&
              knhv::EvaluateTargetEvidenceGate(&manifest, &request, &result) &&
              result.status == knhv::HvStatus::Success &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceReason::None) &&
              result.missing_flags == 0U &&
              knhv::IsTargetEvidenceGateResultValid(&result));

    auto dirty = manifest;
    dirty.flags &= ~knhv::kTargetEvidenceFlagSourceClean;
    Check(state, "target evidence blocks a dirty release source",
          knhv::EvaluateTargetEvidenceGate(&dirty, &request, &result) &&
              result.status == knhv::HvStatus::CapabilityMismatch &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceReason::SourceDirty) &&
              (result.missing_flags & knhv::kTargetEvidenceFlagSourceClean) !=
                  0U);

    auto wrong_generation = request;
    wrong_generation.expected_generation = 10;
    Check(state, "target evidence blocks a stale generation",
          knhv::EvaluateTargetEvidenceGate(&manifest, &wrong_generation,
                                            &result) &&
              result.status == knhv::HvStatus::BootHandoffFailed &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceReason::GenerationMismatch));

    auto wrong_profile = MakeRequest(knhv::TargetEvidenceProfile::WhpManaged);
    Check(state, "target evidence rejects a profile mismatch",
          knhv::EvaluateTargetEvidenceGate(&manifest, &wrong_profile, &result) &&
              result.status == knhv::HvStatus::IncompatibleProvider &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceReason::ProfileMismatch));

    auto not_comparable = manifest;
    not_comparable.verdict = static_cast<std::uint32_t>(
        knhv::TargetEvidenceVerdict::NotComparable);
    Check(state, "target evidence keeps noncomparable performance blocked",
          knhv::EvaluateTargetEvidenceGate(&not_comparable, &request, &result) &&
              result.status == knhv::HvStatus::CapabilityMismatch &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceReason::PerformanceNotComparable));

    auto capability = MakeManifest(
        knhv::TargetEvidenceProfile::NativeIntelL0,
        knhv::TargetEvidenceStage::Capability);
    capability.owner_kind = static_cast<std::uint32_t>(
        knhv::HvOwnerKindV2::Unknown);
    capability.owner_state = static_cast<std::uint32_t>(
        knhv::HvProviderStateV2::Unknown);
    const auto capability_request = MakeRequest(
        knhv::TargetEvidenceProfile::NativeIntelL0,
        knhv::TargetEvidenceStage::Capability);
    Check(state, "capability evidence can precede owner acquisition",
          knhv::IsTargetEvidenceManifestValid(&capability) &&
              knhv::EvaluateTargetEvidenceGate(&capability,
                                                &capability_request, &result) &&
              result.status == knhv::HvStatus::Success);
}

void CheckFallbackProfiles(TestState& state) {
    for (const auto profile : {knhv::TargetEvidenceProfile::WhpManaged,
                               knhv::TargetEvidenceProfile::ExternalL0,
                               knhv::TargetEvidenceProfile::SyntheticLab}) {
        const auto manifest = MakeManifest(
            profile, knhv::TargetEvidenceStage::Nested);
        auto request = MakeRequest(profile, knhv::TargetEvidenceStage::Nested);
        knhv::TargetEvidenceGateResult result = {};
        Check(state, "fallback target evidence profile has an explicit owner",
              knhv::IsTargetEvidenceManifestValid(&manifest) &&
                  knhv::EvaluateTargetEvidenceGate(&manifest, &request,
                                                    &result) &&
                  result.status == knhv::HvStatus::Success);
    }
}

void CheckMalformedInputs(TestState& state) {
    auto manifest = MakeManifest();
    auto request = MakeRequest();
    knhv::TargetEvidenceGateResult result = {};
    manifest.size = 0;
    Check(state, "target evidence reports an invalid manifest deterministically",
          !knhv::EvaluateTargetEvidenceGate(&manifest, &request, &result) &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceReason::InvalidManifest) &&
              knhv::IsTargetEvidenceGateResultValid(&result));
    request.required_flags = 1U << 31;
    const auto valid_manifest = MakeManifest();
    Check(state, "target evidence rejects unknown request flags",
          !knhv::EvaluateTargetEvidenceGate(&valid_manifest, &request,
                                            &result));
    auto forged = MakeManifest();
    const auto valid_request = MakeRequest();
    knhv::EvaluateTargetEvidenceGate(&forged, &valid_request, &result);
    result.reason = static_cast<std::uint32_t>(
        knhv::TargetEvidenceReason::ProfileMismatch);
    Check(state, "target evidence rejects a forged success result",
          !knhv::IsTargetEvidenceGateResultValid(&result));
    Check(state, "target evidence text names profile and verdict states",
          std::string(knhv::TargetEvidenceProfileText(
                          knhv::TargetEvidenceProfile::NativeIntelL0)) ==
                  "native-intel-l0" &&
              std::string(knhv::TargetEvidenceVerdictText(
                          knhv::TargetEvidenceVerdict::NotComparable)) ==
                  "not-comparable");
}

}  // namespace

void RunTargetEvidenceModelContract(TestState& state) {
    CheckManifestValidation(state);
    CheckGateDecisions(state);
    CheckFallbackProfiles(state);
    CheckMalformedInputs(state);
}

}  // namespace knhv_tests
