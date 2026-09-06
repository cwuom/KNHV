#include "test_support.h"

#include "knhv_target_snapshot_gate.h"

#include <array>
#include <cstring>
#include <string>

namespace knhv_tests {
namespace {

constexpr knhv::u32 kPrivateRootMarker = 1U;

void FillDigest(knhv::u8* digest, knhv::u8 seed) {
    for (knhv::u32 index = 0U; index < 32U; ++index) {
        digest[index] = static_cast<knhv::u8>(seed + index);
    }
}

knhv::TargetEvidenceSnapshot MakeSyntheticSnapshot() {
    knhv::TargetEvidenceSnapshot snapshot{};
    snapshot.size = sizeof(snapshot);
    snapshot.version = knhv::kTargetEvidenceSnapshotContractVersion;
    snapshot.profile = static_cast<knhv::u32>(
        knhv::TargetEvidenceProfile::SyntheticLab);
    snapshot.stage = static_cast<knhv::u32>(
        knhv::TargetEvidenceStage::Release);
    snapshot.verdict = static_cast<knhv::u32>(
        knhv::TargetEvidenceVerdict::Pass);
    snapshot.flags =
        knhv::kTargetEvidenceSnapshotFlagOwnerObservation |
        knhv::kTargetEvidenceSnapshotFlagOwnerGate |
        knhv::kTargetEvidenceSnapshotFlagArtifacts |
        knhv::kTargetEvidenceSnapshotFlagSourceClean |
        knhv::kTargetEvidenceSnapshotFlagRecoveryReady |
        knhv::kTargetEvidenceSnapshotFlagSignature |
        knhv::kTargetEvidenceSnapshotFlagSynthetic |
        knhv::kTargetEvidenceSnapshotFlagTimeSynchronized |
        knhv::kTargetEvidenceSnapshotFlagTelemetry |
        knhv::kTargetEvidenceSnapshotFlagNoCriticalFaults |
        knhv::kTargetEvidenceSnapshotFlagPerformance |
        knhv::kTargetEvidenceSnapshotFlagWarningsClear |
        knhv::kTargetEvidenceSnapshotFlagAllowPrivateTestRoot;
    snapshot.artifact_count = 1U;
    snapshot.generation = 7U;
    snapshot.started_tsc = 100U;
    snapshot.ended_tsc = 200U;
    FillDigest(snapshot.build_id, 1U);
    FillDigest(snapshot.artifact_hash, 2U);
    FillDigest(snapshot.manifest_hash, 3U);
    snapshot.owner_observation.size = sizeof(snapshot.owner_observation);
    snapshot.owner_observation.version =
        knhv::kOwnerObservationContractVersion;
    snapshot.owner_observation.cpuid_hypervisor = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Clear);
    snapshot.owner_observation.windows_hypervisor = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Clear);
    snapshot.owner_observation.vbs = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Clear);
    snapshot.owner_observation.hvci = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Clear);
    snapshot.owner_observation.whp_available = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Clear);
    snapshot.owner_observation.provider_device = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Present);
    snapshot.owner_observation.boot_handoff = static_cast<knhv::u32>(
        knhv::OwnerEvidenceState::Clear);
    snapshot.owner_observation.provider_owner = static_cast<knhv::u32>(
        knhv::HvOwnerKindV2::SyntheticLab);
    snapshot.owner_observation.provider_state = static_cast<knhv::u32>(
        knhv::HvProviderStateV2::Active);
    snapshot.owner_observation.generation = snapshot.generation;
    (void)knhv::EvaluateOwnerGate(&snapshot.owner_observation,
                                  &snapshot.owner_gate);
    snapshot.signature.size = sizeof(snapshot.signature);
    snapshot.signature.version =
        knhv::kTargetEvidenceSignatureContractVersion;
    snapshot.signature.status = static_cast<knhv::u32>(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot);
    snapshot.signature.wintrust_status = kPrivateRootMarker;
    snapshot.signature.result_flags =
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted;
    return snapshot;
}

knhv::TargetEvidenceGateRequest MakeRequest(
    knhv::TargetEvidenceProfile profile =
        knhv::TargetEvidenceProfile::SyntheticLab,
    knhv::TargetEvidenceStage stage = knhv::TargetEvidenceStage::Release,
    knhv::u64 generation = 0U) {
    knhv::TargetEvidenceGateRequest request{};
    request.size = sizeof(request);
    request.version = knhv::kTargetEvidenceContractVersion;
    request.profile = static_cast<knhv::u32>(profile);
    request.minimum_stage = static_cast<knhv::u32>(stage);
    request.expected_generation = generation;
    return request;
}

void CheckAbi(TestState& state) {
    Check(state, "snapshot gate result ABI is fixed",
          sizeof(knhv::TargetEvidenceSnapshotGateResult) == 320U);
    const std::array<knhv::TargetEvidenceSnapshotGateStatus, 6> statuses = {
        knhv::TargetEvidenceSnapshotGateStatus::Success,
        knhv::TargetEvidenceSnapshotGateStatus::InvalidArgument,
        knhv::TargetEvidenceSnapshotGateStatus::SnapshotInvalid,
        knhv::TargetEvidenceSnapshotGateStatus::ManifestInvalid,
        knhv::TargetEvidenceSnapshotGateStatus::GateBlocked,
        knhv::TargetEvidenceSnapshotGateStatus::GateInvalid};
    bool named = true;
    for (const auto status : statuses) {
        named = named && std::string(
                             knhv::TargetEvidenceSnapshotGateStatusText(status))
                         != "unknown";
    }
    Check(state, "snapshot gate statuses have stable text", named);
}

void CheckSuccessfulGate(TestState& state) {
    const auto snapshot = MakeSyntheticSnapshot();
    const auto request = MakeRequest();
    knhv::TargetEvidenceSnapshotGateResult result{};
    const auto status = knhv::EvaluateTargetEvidenceSnapshotGate(
        &snapshot, nullptr, 0U, nullptr, 0U, &request, &result);
    Check(state, "snapshot gate accepts a complete synthetic release",
          status == knhv::TargetEvidenceSnapshotGateStatus::Success &&
              result.status == static_cast<knhv::u32>(
                  knhv::TargetEvidenceSnapshotGateStatus::Success) &&
              result.snapshot_status == static_cast<knhv::u32>(
                  knhv::TargetEvidenceSnapshotStatus::Success) &&
              result.gate.status == knhv::HvStatus::Success &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&result));
}

void CheckBlockedGates(TestState& state) {
    const auto snapshot = MakeSyntheticSnapshot();
    auto wrong_profile = MakeRequest(knhv::TargetEvidenceProfile::NativeIntelL0);
    knhv::TargetEvidenceSnapshotGateResult profile_result{};
    const auto profile_status = knhv::EvaluateTargetEvidenceSnapshotGate(
        &snapshot, nullptr, 0U, nullptr, 0U, &wrong_profile,
        &profile_result);
    auto wrong_generation = MakeRequest(
        knhv::TargetEvidenceProfile::SyntheticLab,
        knhv::TargetEvidenceStage::Release, snapshot.generation + 1U);
    knhv::TargetEvidenceSnapshotGateResult generation_result{};
    const auto generation_status =
        knhv::EvaluateTargetEvidenceSnapshotGate(
            &snapshot, nullptr, 0U, nullptr, 0U, &wrong_generation,
            &generation_result);
    Check(state, "snapshot gate reports profile mismatch as blocked",
          profile_status == knhv::TargetEvidenceSnapshotGateStatus::GateBlocked &&
              profile_result.gate.reason == static_cast<knhv::u32>(
                  knhv::TargetEvidenceReason::ProfileMismatch) &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&profile_result));
    Check(state, "snapshot gate reports generation mismatch as blocked",
          generation_status ==
                  knhv::TargetEvidenceSnapshotGateStatus::GateBlocked &&
              generation_result.gate.reason == static_cast<knhv::u32>(
                  knhv::TargetEvidenceReason::GenerationMismatch) &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&generation_result));
    auto low_stage_snapshot = snapshot;
    low_stage_snapshot.stage = static_cast<knhv::u32>(
        knhv::TargetEvidenceStage::Capability);
    const auto stage_request = MakeRequest(
        knhv::TargetEvidenceProfile::SyntheticLab,
        knhv::TargetEvidenceStage::Release);
    knhv::TargetEvidenceSnapshotGateResult stage_result{};
    const auto stage_status = knhv::EvaluateTargetEvidenceSnapshotGate(
        &low_stage_snapshot, nullptr, 0U, nullptr, 0U, &stage_request,
        &stage_result);
    Check(state, "snapshot gate reports an incomplete stage as blocked",
          stage_status == knhv::TargetEvidenceSnapshotGateStatus::GateBlocked &&
              stage_result.gate.reason == static_cast<knhv::u32>(
                  knhv::TargetEvidenceReason::StageIncomplete) &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&stage_result));
}

void CheckInvalidInputs(TestState& state) {
    const auto snapshot = MakeSyntheticSnapshot();
    const auto request = MakeRequest();
    knhv::TargetEvidenceSnapshotGateResult result{};
    Check(state, "snapshot gate rejects a null snapshot",
          knhv::EvaluateTargetEvidenceSnapshotGate(
              nullptr, nullptr, 0U, nullptr, 0U, &request, &result) ==
              knhv::TargetEvidenceSnapshotGateStatus::SnapshotInvalid &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&result));
    auto invalid_request = request;
    invalid_request.profile = 0U;
    Check(state, "snapshot gate rejects an unknown profile",
          knhv::EvaluateTargetEvidenceSnapshotGate(
              &snapshot, nullptr, 0U, nullptr, 0U, &invalid_request, &result) ==
              knhv::TargetEvidenceSnapshotGateStatus::InvalidArgument &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&result));
    auto invalid_snapshot = snapshot;
    invalid_snapshot.flags |=
        knhv::kTargetEvidenceSnapshotFlagHardwareEvidence;
    Check(state, "snapshot gate rejects synthetic hardware evidence",
          knhv::EvaluateTargetEvidenceSnapshotGate(
              &invalid_snapshot, nullptr, 0U, nullptr, 0U, &request, &result) ==
              knhv::TargetEvidenceSnapshotGateStatus::SnapshotInvalid &&
              knhv::IsTargetEvidenceSnapshotGateResultValid(&result));
    auto forged = result;
    forged.status = 0xFFFFFFFFU;
    Check(state, "snapshot gate result rejects an unknown status",
          !knhv::IsTargetEvidenceSnapshotGateResultValid(&forged));
}

}  // namespace

void RunTargetEvidenceSnapshotGateContract(TestState& state) {
    CheckAbi(state);
    CheckSuccessfulGate(state);
    CheckBlockedGates(state);
    CheckInvalidInputs(state);
}

}  // namespace knhv_tests
