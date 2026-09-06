#include "test_support.h"

#include "knhv_target_evidence_writer.h"

#include <array>
#include <cstdint>
#include <string>

namespace knhv_tests {
namespace {

void FillDigest(knhv::u8 (&digest)[32], knhv::u8 value) {
    for (knhv::u8& byte : digest) byte = value;
}

knhv::TargetEvidenceManifest MakeManifest(
    knhv::TargetEvidenceProfile profile =
        knhv::TargetEvidenceProfile::NativeIntelL0,
    knhv::TargetEvidenceStage stage = knhv::TargetEvidenceStage::Release,
    knhv::TargetEvidenceVerdict verdict =
        knhv::TargetEvidenceVerdict::Pass) {
    knhv::TargetEvidenceManifest manifest{};
    manifest.size = sizeof(manifest);
    manifest.version = knhv::kTargetEvidenceContractVersion;
    manifest.profile = static_cast<knhv::u32>(profile);
    manifest.stage = static_cast<knhv::u32>(stage);
    manifest.verdict = static_cast<knhv::u32>(verdict);
    manifest.flags = knhv::RequiredTargetEvidenceFlags(profile, stage);
    switch (profile) {
        case knhv::TargetEvidenceProfile::NativeIntelL0:
            manifest.owner_kind = static_cast<knhv::u32>(
                knhv::HvOwnerKindV2::KnhvBootL0);
            manifest.owner_state = static_cast<knhv::u32>(
                knhv::HvProviderStateV2::Active);
            break;
        case knhv::TargetEvidenceProfile::WhpManaged:
            manifest.owner_kind = static_cast<knhv::u32>(
                knhv::HvOwnerKindV2::WhpManaged);
            manifest.owner_state = static_cast<knhv::u32>(
                knhv::HvProviderStateV2::Available);
            break;
        case knhv::TargetEvidenceProfile::ExternalL0:
            manifest.owner_kind = static_cast<knhv::u32>(
                knhv::HvOwnerKindV2::ExternalL0);
            manifest.owner_state = static_cast<knhv::u32>(
                knhv::HvProviderStateV2::Conflict);
            break;
        case knhv::TargetEvidenceProfile::SyntheticLab:
            manifest.owner_kind = static_cast<knhv::u32>(
                knhv::HvOwnerKindV2::SyntheticLab);
            manifest.owner_state = static_cast<knhv::u32>(
                knhv::HvProviderStateV2::Active);
            break;
        default:
            break;
    }
    manifest.cpu_count = 8U;
    manifest.cpu_valid_count = 8U;
    manifest.artifact_count = 12U;
    manifest.generation = 9U;
    manifest.started_tsc = 100U;
    manifest.ended_tsc = 200U;
    FillDigest(manifest.machine_id, 1U);
    FillDigest(manifest.build_id, 2U);
    FillDigest(manifest.artifact_hash, 3U);
    FillDigest(manifest.capability_hash, 4U);
    FillDigest(manifest.manifest_hash, 5U);
    return manifest;
}

knhv::TargetEvidenceSignatureResult MakeSignature(
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

knhv::TargetEvidenceManifestWriteRequest MakeRequest(
    const knhv::TargetEvidenceManifest& manifest,
    const knhv::TargetEvidenceSignatureResult& signature,
    knhv::u32 flags) {
    knhv::TargetEvidenceManifestWriteRequest request{};
    request.size = sizeof(request);
    request.version = knhv::kTargetEvidenceWriterContractVersion;
    request.flags = flags;
    request.candidate = manifest;
    request.signature = signature;
    return request;
}

knhv::u32 SyntheticFlags(bool commit = true, bool source_clean = true,
                         bool allow_private_root = true) {
    knhv::u32 flags = knhv::kTargetEvidenceWriterFlagAllowSynthetic;
    if (commit) flags |= knhv::kTargetEvidenceWriterFlagCommitSignature;
    if (source_clean) {
        flags |= knhv::kTargetEvidenceWriterFlagSourceCleanObserved;
    }
    if (allow_private_root) {
        flags |= knhv::kTargetEvidenceWriterFlagAllowPrivateTestRoot;
    }
    return flags;
}

knhv::u32 NativeReleaseFlags(bool allow_private_root = false) {
    knhv::u32 flags = knhv::kTargetEvidenceWriterFlagHardwareEvidence |
                      knhv::kTargetEvidenceWriterFlagSourceCleanObserved |
                      knhv::kTargetEvidenceWriterFlagCommitSignature;
    if (allow_private_root) {
        flags |= knhv::kTargetEvidenceWriterFlagAllowPrivateTestRoot;
    }
    return flags;
}

void CheckAbiAndStatus(TestState& state) {
    Check(state, "manifest writer ABI is fixed",
          sizeof(knhv::TargetEvidenceManifestWriteRequest) == 296U &&
              sizeof(knhv::TargetEvidenceManifestWriteResult) == 280U);

    const std::array<knhv::TargetEvidenceWriterStatus, 9> statuses = {
        knhv::TargetEvidenceWriterStatus::Success,
        knhv::TargetEvidenceWriterStatus::InvalidArgument,
        knhv::TargetEvidenceWriterStatus::InvalidManifest,
        knhv::TargetEvidenceWriterStatus::SignatureRequired,
        knhv::TargetEvidenceWriterStatus::SignatureUntrusted,
        knhv::TargetEvidenceWriterStatus::HardwareEvidenceRequired,
        knhv::TargetEvidenceWriterStatus::SyntheticPolicyViolation,
        knhv::TargetEvidenceWriterStatus::SourceDirty,
        knhv::TargetEvidenceWriterStatus::GenerationInvalid};
    bool all_named = true;
    for (const auto status : statuses) {
        all_named = all_named &&
                    std::string(knhv::TargetEvidenceWriterStatusText(status)) !=
                        "unknown";
    }
    Check(state, "manifest writer statuses have stable text", all_named);
}

void CheckSyntheticPolicy(TestState& state) {
    const auto candidate = MakeManifest(
        knhv::TargetEvidenceProfile::SyntheticLab);
    const auto signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot, 1U,
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted);
    auto request = MakeRequest(candidate, signature, SyntheticFlags());
    knhv::TargetEvidenceManifestWriteResult result{};
    Check(state, "synthetic release accepts explicit lab policy",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                    knhv::TargetEvidenceWriterStatus::Success) &&
              result.reason == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceReason::None) &&
              (result.manifest.flags &
               knhv::kTargetEvidenceFlagSignatureVerified) != 0U &&
              knhv::IsTargetEvidenceManifestWriteResultValid(&result));

    request.flags &= ~knhv::kTargetEvidenceWriterFlagAllowSynthetic;
    Check(state, "synthetic evidence requires the allow flag",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       SyntheticPolicyViolation) &&
              result.reason == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceReason::InvalidRequest) &&
              knhv::IsTargetEvidenceManifestWriteResultValid(&result));

    request = MakeRequest(candidate, signature,
                          SyntheticFlags() |
                              knhv::kTargetEvidenceWriterFlagHardwareEvidence);
    Check(state, "synthetic evidence cannot claim hardware collection",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       SyntheticPolicyViolation));

    auto hardware_claim = candidate;
    hardware_claim.flags |= knhv::kTargetEvidenceFlagHardwareTarget;
    request = MakeRequest(hardware_claim, signature, SyntheticFlags());
    Check(state, "synthetic evidence cannot carry a hardware target bit",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       SyntheticPolicyViolation));
}

void CheckHardwareAndSourcePolicy(TestState& state) {
    const auto signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::InvalidArgument);
    const auto capability = MakeManifest(
        knhv::TargetEvidenceProfile::NativeIntelL0,
        knhv::TargetEvidenceStage::Capability);
    auto request = MakeRequest(capability, signature, 0U);
    knhv::TargetEvidenceManifestWriteResult result{};
    Check(state, "native capability requires target hardware evidence",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       HardwareEvidenceRequired) &&
              result.reason == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceReason::
                                       CapabilityIncomplete));

    request.flags = knhv::kTargetEvidenceWriterFlagHardwareEvidence;
    Check(state, "native capability passes with hardware evidence",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::Success));

    const auto synthetic = MakeManifest(
        knhv::TargetEvidenceProfile::SyntheticLab);
    const auto private_signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot, 1U,
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted);
    request = MakeRequest(synthetic, private_signature,
                          SyntheticFlags(true, false, true));
    Check(state, "source clean requires an observed clean source",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::SourceDirty) &&
              result.reason == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceReason::SourceDirty));
}

void CheckSignaturePolicy(TestState& state) {
    const auto candidate = MakeManifest(
        knhv::TargetEvidenceProfile::NativeIntelL0);
    knhv::TargetEvidenceManifestWriteResult result{};
    auto request = MakeRequest(
        candidate,
        MakeSignature(knhv::TargetEvidenceSignatureStatus::InvalidArgument),
        NativeReleaseFlags());
    Check(state, "native release requires a signature result",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       SignatureRequired) &&
              result.reason == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceReason::
                                       SignatureUnverified));

    request.signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::NotSigned, 1U);
    Check(state, "native release rejects an unsigned image",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       SignatureUntrusted));

    request.signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::Trusted);
    Check(state, "native release commits a trusted signature",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::Success) &&
              (result.manifest.flags &
               knhv::kTargetEvidenceFlagSignatureVerified) != 0U);

    request.flags = NativeReleaseFlags(true);
    request.signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot, 1U,
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted);
    Check(state, "native release rejects a private test root",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::
                                       SignatureUntrusted));
}

void CheckMalformedRecords(TestState& state) {
    const auto candidate = MakeManifest(
        knhv::TargetEvidenceProfile::SyntheticLab);
    const auto signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot, 1U,
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted);
    auto request = MakeRequest(candidate, signature, SyntheticFlags());
    knhv::TargetEvidenceManifestWriteResult result{};
    request.flags |= 1U << 31;
    Check(state, "writer request rejects unknown flags",
          !knhv::IsTargetEvidenceManifestWriteRequestValid(&request) &&
              !knhv::BuildTargetEvidenceManifest(&request, &result) &&
              knhv::IsTargetEvidenceManifestWriteResultValid(&result));

    request = MakeRequest(candidate, signature, SyntheticFlags());
    request.reserved = 1U;
    Check(state, "writer request rejects reserved bits",
          !knhv::IsTargetEvidenceManifestWriteRequestValid(&request));

    request = MakeRequest(candidate, signature, SyntheticFlags());
    request.size = sizeof(request) - 1U;
    Check(state, "writer request rejects a truncated record",
          !knhv::IsTargetEvidenceManifestWriteRequestValid(&request));

    auto invalid_candidate = candidate;
    invalid_candidate.stage = static_cast<knhv::u32>(
        knhv::TargetEvidenceStage::Capability);
    invalid_candidate.verdict = static_cast<knhv::u32>(
        knhv::TargetEvidenceVerdict::Pass);
    invalid_candidate.generation = 0U;
    request = MakeRequest(invalid_candidate, signature, SyntheticFlags());
    Check(state, "writer request rejects a stale pass generation",
          !knhv::IsTargetEvidenceManifestWriteRequestValid(&request) &&
              !knhv::BuildTargetEvidenceManifest(&request, &result));

    auto success = MakeRequest(candidate, signature, SyntheticFlags());
    knhv::BuildTargetEvidenceManifest(&success, &result);
    result.reason = static_cast<knhv::u32>(
        knhv::TargetEvidenceReason::InvalidManifest);
    Check(state, "writer rejects a forged success reason",
          !knhv::IsTargetEvidenceManifestWriteResultValid(&result));

    knhv::TargetEvidenceManifestWriteResult forged{};
    forged.size = sizeof(forged);
    forged.version = knhv::kTargetEvidenceWriterContractVersion;
    forged.status = static_cast<knhv::u32>(
        knhv::TargetEvidenceWriterStatus::SignatureUntrusted);
    forged.reason = static_cast<knhv::u32>(
        knhv::TargetEvidenceReason::SignatureUnverified);
    forged.manifest.version = knhv::kTargetEvidenceContractVersion;
    Check(state, "writer rejects a partial failure manifest",
          !knhv::IsTargetEvidenceManifestWriteResultValid(&forged));
}

void CheckEarlyCollection(TestState& state) {
    auto inventory = MakeManifest(knhv::TargetEvidenceProfile::SyntheticLab,
                                  knhv::TargetEvidenceStage::Inventory,
                                  knhv::TargetEvidenceVerdict::Ready);
    inventory.generation = 0U;
    const auto no_signature = MakeSignature(
        knhv::TargetEvidenceSignatureStatus::InvalidArgument);
    const auto request = MakeRequest(
        inventory, no_signature,
        knhv::kTargetEvidenceWriterFlagAllowSynthetic);
    knhv::TargetEvidenceManifestWriteResult result{};
    Check(state, "inventory snapshots can remain unsigned",
          knhv::BuildTargetEvidenceManifest(&request, &result) &&
              result.status == static_cast<knhv::u32>(
                                   knhv::TargetEvidenceWriterStatus::Success) &&
              result.manifest.generation == 0U);
}

}  // namespace

void RunTargetEvidenceWriterContract(TestState& state) {
    CheckAbiAndStatus(state);
    CheckSyntheticPolicy(state);
    CheckHardwareAndSourcePolicy(state);
    CheckSignaturePolicy(state);
    CheckMalformedRecords(state);
    CheckEarlyCollection(state);
}

}  // namespace knhv_tests
