#include "test_support.h"

#include "knhv_target_collector.h"
#include "knhv_target_snapshot_codec.h"

#include <array>
#include <cstring>
#include <string>

namespace knhv_tests {
namespace {

void FillDigest(knhv::u8 (&digest)[32], knhv::u8 seed) {
    for (knhv::u8& byte : digest) {
        byte = seed++;
    }
}

void FillDigest(std::array<knhv::u8, 32>& digest, knhv::u8 seed) {
    for (knhv::u8& byte : digest) {
        byte = seed++;
    }
}

knhv::TargetEvidenceSnapshot MakeInventorySnapshot() {
    knhv::TargetEvidenceSnapshot snapshot{};
    snapshot.size = sizeof(snapshot);
    snapshot.version = knhv::kTargetEvidenceSnapshotContractVersion;
    snapshot.profile = static_cast<knhv::u32>(
        knhv::TargetEvidenceProfile::SyntheticLab);
    snapshot.stage = static_cast<knhv::u32>(
        knhv::TargetEvidenceStage::Inventory);
    snapshot.verdict = static_cast<knhv::u32>(
        knhv::TargetEvidenceVerdict::Ready);
    snapshot.flags = knhv::kTargetEvidenceSnapshotFlagSynthetic;
    return snapshot;
}

knhv::TargetEvidenceSnapshot MakeBoundSnapshot() {
    auto snapshot = MakeInventorySnapshot();
    snapshot.flags |= knhv::kTargetEvidenceSnapshotFlagArtifacts |
                      knhv::kTargetEvidenceSnapshotFlagSourceClean |
                      knhv::kTargetEvidenceSnapshotFlagSignature |
                      knhv::kTargetEvidenceSnapshotFlagAllowPrivateTestRoot;
    snapshot.artifact_count = 1U;
    FillDigest(snapshot.build_id, 1U);
    FillDigest(snapshot.artifact_hash, 2U);
    FillDigest(snapshot.manifest_hash, 3U);
    snapshot.signature.size = sizeof(snapshot.signature);
    snapshot.signature.version =
        knhv::kTargetEvidenceSignatureContractVersion;
    snapshot.signature.status = static_cast<knhv::u32>(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot);
    snapshot.signature.wintrust_status = 1U;
    snapshot.signature.result_flags =
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted;
    return snapshot;
}

knhv::TargetEvidenceCollectorBinding MakeBinding(
    const knhv::TargetEvidenceSnapshot& snapshot,
    const knhv::u8* package_digest, knhv::u32 cpu_count = 0U,
    knhv::u32 vmx_count = 0U) {
    knhv::TargetEvidenceCollectorBinding binding{};
    binding.size = sizeof(binding);
    binding.version = knhv::kTargetEvidenceCollectorContractVersion;
    binding.flags = knhv::kTargetEvidenceCollectorFlagDigestVerified;
    if (snapshot.profile == static_cast<knhv::u32>(
                             knhv::TargetEvidenceProfile::SyntheticLab)) {
        binding.flags |= knhv::kTargetEvidenceCollectorFlagSynthetic;
    }
    if ((snapshot.flags & knhv::kTargetEvidenceSnapshotFlagHardwareEvidence) !=
        0U) {
        binding.flags |= knhv::kTargetEvidenceCollectorFlagHardware;
    }
    if ((snapshot.flags & knhv::kTargetEvidenceSnapshotFlagSourceClean) != 0U) {
        binding.flags |= knhv::kTargetEvidenceCollectorFlagSourceClean;
    }
    if ((snapshot.flags & knhv::kTargetEvidenceSnapshotFlagSignature) != 0U) {
        binding.flags |= knhv::kTargetEvidenceCollectorFlagSignature;
    }
    binding.capture_id = 41U;
    binding.generation = snapshot.generation;
    binding.started_tsc = snapshot.started_tsc;
    binding.ended_tsc = snapshot.ended_tsc;
    binding.cpu_sample_count = cpu_count;
    binding.vmx_sample_count = vmx_count;
    FillDigest(binding.collector_id, 11U);
    FillDigest(binding.package_digest, 0U);
    std::memcpy(binding.package_digest, package_digest,
                sizeof(binding.package_digest));
    FillDigest(binding.collector_build_id, 21U);
    if ((snapshot.flags & knhv::kTargetEvidenceSnapshotFlagArtifacts) != 0U) {
        std::memcpy(binding.artifact_hash, snapshot.artifact_hash,
                    sizeof(binding.artifact_hash));
    }
    if ((snapshot.flags & knhv::kTargetEvidenceSnapshotFlagSignature) != 0U) {
        binding.signature = snapshot.signature;
    }
    return binding;
}

void CheckAbiAndTexts(TestState& state) {
    Check(state, "collector binding ABI is fixed",
          sizeof(knhv::TargetEvidenceCollectorBinding) == 216U &&
              sizeof(knhv::TargetEvidenceCollectorBindingResult) == 40U);
    const std::array<knhv::TargetEvidenceCollectorStatus, 12> statuses = {
        knhv::TargetEvidenceCollectorStatus::Success,
        knhv::TargetEvidenceCollectorStatus::InvalidArgument,
        knhv::TargetEvidenceCollectorStatus::SnapshotInvalid,
        knhv::TargetEvidenceCollectorStatus::DigestMissing,
        knhv::TargetEvidenceCollectorStatus::DigestMismatch,
        knhv::TargetEvidenceCollectorStatus::IdentityMissing,
        knhv::TargetEvidenceCollectorStatus::GenerationMismatch,
        knhv::TargetEvidenceCollectorStatus::TimestampMismatch,
        knhv::TargetEvidenceCollectorStatus::CoverageMismatch,
        knhv::TargetEvidenceCollectorStatus::FlagMismatch,
        knhv::TargetEvidenceCollectorStatus::SignatureMismatch,
        knhv::TargetEvidenceCollectorStatus::FirstFailureMismatch};
    const std::array<knhv::TargetEvidenceCollectorReason, 12> reasons = {
        knhv::TargetEvidenceCollectorReason::None,
        knhv::TargetEvidenceCollectorReason::InvalidRequest,
        knhv::TargetEvidenceCollectorReason::Snapshot,
        knhv::TargetEvidenceCollectorReason::DigestMissing,
        knhv::TargetEvidenceCollectorReason::DigestMismatch,
        knhv::TargetEvidenceCollectorReason::IdentityMissing,
        knhv::TargetEvidenceCollectorReason::GenerationMismatch,
        knhv::TargetEvidenceCollectorReason::TimestampMismatch,
        knhv::TargetEvidenceCollectorReason::CoverageMismatch,
        knhv::TargetEvidenceCollectorReason::FlagMismatch,
        knhv::TargetEvidenceCollectorReason::SignatureMismatch,
        knhv::TargetEvidenceCollectorReason::FirstFailureMismatch};
    bool named = true;
    for (const auto status : statuses) {
        named = named && std::string(
                             knhv::TargetEvidenceCollectorStatusText(status)) !=
                         "unknown";
    }
    for (const auto reason : reasons) {
        named = named && std::string(
                             knhv::TargetEvidenceCollectorReasonText(reason)) !=
                         "unknown";
    }
    Check(state, "collector binding statuses have stable text", named);
}

void CheckSuccessfulBindings(TestState& state) {
    const auto snapshot = MakeInventorySnapshot();
    std::array<knhv::u8, 32> digest{};
    FillDigest(digest, 31U);
    const auto binding = MakeBinding(snapshot, digest.data());
    knhv::TargetEvidenceCollectorBindingResult result{};
    const auto status = knhv::ValidateTargetEvidenceCollectorBinding(
        &snapshot, nullptr, 0U, nullptr, 0U, digest.data(), &binding,
        &result);
    Check(state, "collector binding accepts an inventory snapshot",
          status == knhv::TargetEvidenceCollectorStatus::Success &&
              result.status == static_cast<knhv::u32>(
                  knhv::TargetEvidenceCollectorStatus::Success) &&
              result.capture_id == binding.capture_id &&
              knhv::IsTargetEvidenceCollectorBindingResultValid(&result));

    const auto bound_snapshot = MakeBoundSnapshot();
    const auto bound = MakeBinding(bound_snapshot, digest.data());
    knhv::TargetEvidenceCollectorBindingResult bound_result{};
    const auto bound_status = knhv::ValidateTargetEvidenceCollectorBinding(
        &bound_snapshot, nullptr, 0U, nullptr, 0U, digest.data(), &bound,
        &bound_result);
    Check(state, "collector binding carries artifact and signature identity",
          knhv::IsTargetEvidenceCollectorBindingValid(&bound) &&
              bound_status == knhv::TargetEvidenceCollectorStatus::Success &&
              knhv::IsTargetEvidenceCollectorBindingResultValid(&bound_result));
}

void CheckCodecBindingPath(TestState& state) {
    const auto snapshot = MakeInventorySnapshot();
    std::array<knhv::u8, 640> encoded{};
    knhv::u32 written = 0U;
    const auto encode_status = knhv::EncodeTargetEvidenceSnapshotPackage(
        &snapshot, nullptr, 0U, nullptr, 0U, encoded.data(),
        static_cast<knhv::u32>(encoded.size()), &written);
    std::array<knhv::u8, knhv::kTargetEvidenceSnapshotWireDigestSize> digest{};
    const auto digest_status =
        knhv::GetTargetEvidenceSnapshotPackageDigest(
            encoded.data(), written, digest.data());
    const auto binding = MakeBinding(snapshot, digest.data());
    knhv::TargetEvidenceCollectorBindingResult result{};
    const auto binding_status = knhv::ValidateTargetEvidenceCollectorBinding(
        &snapshot, nullptr, 0U, nullptr, 0U, digest.data(), &binding,
        &result);
    Check(state, "collector binding consumes a verified codec digest",
          encode_status == knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              digest_status ==
                  knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              binding_status == knhv::TargetEvidenceCollectorStatus::Success &&
              knhv::IsTargetEvidenceCollectorBindingResultValid(&result));
}

void CheckDigestAndIdentityFailures(TestState& state) {
    const auto snapshot = MakeInventorySnapshot();
    std::array<knhv::u8, 32> digest{};
    FillDigest(digest, 31U);
    const auto binding = MakeBinding(snapshot, digest.data());
    knhv::TargetEvidenceCollectorBindingResult result{};
    std::array<knhv::u8, 32> empty_digest{};
    const auto missing = knhv::ValidateTargetEvidenceCollectorBinding(
        &snapshot, nullptr, 0U, nullptr, 0U, empty_digest.data(), &binding,
        &result);
    Check(state, "collector binding rejects a missing package digest",
          missing == knhv::TargetEvidenceCollectorStatus::DigestMissing &&
              knhv::IsTargetEvidenceCollectorBindingResultValid(&result));

    auto wrong_digest = digest;
    wrong_digest[0] ^= 1U;
    const auto mismatch = knhv::ValidateTargetEvidenceCollectorBinding(
        &snapshot, nullptr, 0U, nullptr, 0U, wrong_digest.data(), &binding,
        &result);
    Check(state, "collector binding rejects a digest mismatch",
          mismatch == knhv::TargetEvidenceCollectorStatus::DigestMismatch &&
              knhv::IsTargetEvidenceCollectorBindingResultValid(&result));

    auto no_identity = binding;
    std::memset(no_identity.collector_id, 0, sizeof(no_identity.collector_id));
    Check(state, "collector binding rejects a missing collector identity",
          !knhv::IsTargetEvidenceCollectorBindingValid(&no_identity) &&
              knhv::ValidateTargetEvidenceCollectorBinding(
                  &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
                  &no_identity, &result) ==
                  knhv::TargetEvidenceCollectorStatus::IdentityMissing);

    auto no_package_digest = binding;
    std::memset(no_package_digest.package_digest, 0,
                sizeof(no_package_digest.package_digest));
    Check(state, "collector binding reports a missing stored digest",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &no_package_digest, &result) ==
              knhv::TargetEvidenceCollectorStatus::DigestMissing);
}

void CheckConsistencyFailures(TestState& state) {
    const auto snapshot = MakeBoundSnapshot();
    std::array<knhv::u8, 32> digest{};
    FillDigest(digest, 31U);
    const auto binding = MakeBinding(snapshot, digest.data());
    knhv::TargetEvidenceCollectorBindingResult result{};

    auto wrong_generation = binding;
    ++wrong_generation.generation;
    Check(state, "collector binding rejects a generation mismatch",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &wrong_generation, &result) ==
              knhv::TargetEvidenceCollectorStatus::GenerationMismatch);

    auto wrong_timestamp = binding;
    ++wrong_timestamp.ended_tsc;
    Check(state, "collector binding rejects a timestamp mismatch",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &wrong_timestamp, &result) ==
              knhv::TargetEvidenceCollectorStatus::TimestampMismatch);

    auto wrong_flags = binding;
    wrong_flags.flags &= ~knhv::kTargetEvidenceCollectorFlagSourceClean;
    Check(state, "collector binding rejects a flag mismatch",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &wrong_flags, &result) ==
              knhv::TargetEvidenceCollectorStatus::FlagMismatch);

    auto wrong_artifact = binding;
    wrong_artifact.artifact_hash[0] ^= 1U;
    Check(state, "collector binding rejects an artifact hash mismatch",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &wrong_artifact, &result) ==
              knhv::TargetEvidenceCollectorStatus::DigestMismatch);

    auto wrong_signature = binding;
    wrong_signature.signature.wintrust_status = 2U;
    Check(state, "collector binding rejects a signature mismatch",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &wrong_signature, &result) ==
              knhv::TargetEvidenceCollectorStatus::SignatureMismatch);

    auto failed_snapshot = snapshot;
    failed_snapshot.verdict = static_cast<knhv::u32>(
        knhv::TargetEvidenceVerdict::Fail);
    auto failed_binding = binding;
    failed_binding.first_failure_code = 17U;
    failed_binding.flags |= knhv::kTargetEvidenceCollectorFlagFirstFailure;
    Check(state, "collector binding permits a first failure on failed evidence",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &failed_snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &failed_binding, &result) ==
              knhv::TargetEvidenceCollectorStatus::Success);

    failed_binding = binding;
    failed_binding.first_failure_code = 17U;
    failed_binding.flags |= knhv::kTargetEvidenceCollectorFlagFirstFailure;
    Check(state, "collector binding rejects a first failure on pass evidence",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &snapshot, nullptr, 0U, nullptr, 0U, digest.data(),
              &failed_binding, &result) ==
              knhv::TargetEvidenceCollectorStatus::FirstFailureMismatch);
}

void CheckInvalidInputs(TestState& state) {
    const auto snapshot = MakeInventorySnapshot();
    std::array<knhv::u8, 32> digest{};
    FillDigest(digest, 31U);
    const auto binding = MakeBinding(snapshot, digest.data());
    knhv::TargetEvidenceCollectorBindingResult result{};
    Check(state, "collector binding reports invalid snapshots",
          knhv::ValidateTargetEvidenceCollectorBinding(
              nullptr, nullptr, 0U, nullptr, 0U, digest.data(), &binding,
              &result) == knhv::TargetEvidenceCollectorStatus::InvalidArgument);

    auto bad_snapshot = snapshot;
    bad_snapshot.flags |= knhv::kTargetEvidenceSnapshotFlagHardwareEvidence;
    Check(state, "collector binding blocks an invalid snapshot profile",
          knhv::ValidateTargetEvidenceCollectorBinding(
              &bad_snapshot, nullptr, 0U, nullptr, 0U, digest.data(), &binding,
              &result) == knhv::TargetEvidenceCollectorStatus::SnapshotInvalid);

    auto bad_result = result;
    bad_result.status = 0xFFFFFFFFU;
    Check(state, "collector binding result rejects an unknown status",
          !knhv::IsTargetEvidenceCollectorBindingResultValid(&bad_result));
    bad_result = {};
    bad_result.size = sizeof(bad_result);
    bad_result.version = knhv::kTargetEvidenceCollectorContractVersion;
    bad_result.status = static_cast<knhv::u32>(
        knhv::TargetEvidenceCollectorStatus::Success);
    bad_result.reason = static_cast<knhv::u32>(
        knhv::TargetEvidenceCollectorReason::None);
    Check(state, "collector binding result rejects success without identity",
          !knhv::IsTargetEvidenceCollectorBindingResultValid(&bad_result));
}

}  // namespace

void RunTargetEvidenceCollectorContract(TestState& state) {
    CheckAbiAndTexts(state);
    CheckSuccessfulBindings(state);
    CheckCodecBindingPath(state);
    CheckDigestAndIdentityFailures(state);
    CheckConsistencyFailures(state);
    CheckInvalidInputs(state);
}

}  // namespace knhv_tests
