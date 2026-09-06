#include "knhv_target_snapshot.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTargetEvidenceSnapshotContractVersion &&
           size >= required && size <= kTargetEvidenceSnapshotMaxStructSize;
}

bool IsProfileValid(u32 value) {
    return value >= static_cast<u32>(TargetEvidenceProfile::NativeIntelL0) &&
           value <= static_cast<u32>(TargetEvidenceProfile::SyntheticLab);
}

bool IsStageValid(u32 value) {
    return value <= static_cast<u32>(TargetEvidenceStage::Release);
}

bool IsVerdictValid(u32 value) {
    return value <= static_cast<u32>(TargetEvidenceVerdict::NotComparable);
}

bool HasFlag(const TargetEvidenceSnapshot& snapshot, u32 flag) {
    return (snapshot.flags & flag) != 0U;
}

bool IsDigestNonZero(const u8* digest) {
    if (digest == nullptr) return false;
    for (u32 index = 0U; index < 32U; ++index) {
        if (digest[index] != 0U) return true;
    }
    return false;
}

bool IsZeroBytes(const void* value, u32 size) {
    if (value == nullptr) return false;
    const u8* bytes = reinterpret_cast<const u8*>(value);
    for (u32 index = 0U; index < size; ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

bool AreBytesEqual(const void* left, const void* right, u32 size) {
    if (left == nullptr || right == nullptr) return false;
    const u8* left_bytes = reinterpret_cast<const u8*>(left);
    const u8* right_bytes = reinterpret_cast<const u8*>(right);
    for (u32 index = 0U; index < size; ++index) {
        if (left_bytes[index] != right_bytes[index]) return false;
    }
    return true;
}

bool IsCompleteCpuMatrix(const CpuMatrixSummary& matrix) {
    return matrix.state == static_cast<u32>(CpuMatrixState::CompleteUniform) &&
           matrix.expected_count != 0U &&
           matrix.sample_count == matrix.expected_count &&
           matrix.valid_count == matrix.expected_count &&
           matrix.invalid_count == 0U &&
           (matrix.flags & kCpuMatrixSummarySamplesComplete) != 0U;
}

bool IsCompleteVmxMatrix(const VmxCapabilityMatrix& matrix) {
    return matrix.state ==
               static_cast<u32>(VmxCapabilityMatrixState::CompleteUniform) &&
           matrix.expected_count != 0U &&
           matrix.sample_count == matrix.expected_count &&
           matrix.valid_count == matrix.expected_count &&
           matrix.invalid_count == 0U &&
           (matrix.flags & kVmxMatrixSamplesComplete) != 0U;
}

bool IsOwnerActionForProfile(TargetEvidenceProfile profile,
                             const OwnerGateResult& gate) {
    const auto action = static_cast<OwnerGateAction>(gate.action);
    const auto owner = static_cast<HvOwnerKindV2>(gate.owner);
    switch (profile) {
        case TargetEvidenceProfile::NativeIntelL0:
            return action == OwnerGateAction::AcquireNative &&
                   gate.status == HvStatus::Success &&
                   owner == HvOwnerKindV2::KnhvBootL0;
        case TargetEvidenceProfile::WhpManaged:
            return action == OwnerGateAction::UseWhp &&
                   gate.status == HvStatus::Success &&
                   owner == HvOwnerKindV2::WhpManaged;
        case TargetEvidenceProfile::ExternalL0:
            return action == OwnerGateAction::UseExternalProvider &&
                   gate.status == HvStatus::IncompatibleProvider &&
                   owner == HvOwnerKindV2::ExternalL0;
        case TargetEvidenceProfile::SyntheticLab:
            return action == OwnerGateAction::UseSynthetic &&
                   gate.status == HvStatus::Success &&
                   owner == HvOwnerKindV2::SyntheticLab;
        default:
            return false;
    }
}

bool IsOwnerEvidencePresent(const TargetEvidenceSnapshot& snapshot) {
    return HasFlag(snapshot, kTargetEvidenceSnapshotFlagOwnerObservation) &&
           HasFlag(snapshot, kTargetEvidenceSnapshotFlagOwnerGate);
}

bool IsCapabilityComplete(const TargetEvidenceSnapshot& snapshot) {
    if (!HasFlag(snapshot, kTargetEvidenceSnapshotFlagCpuMatrix) ||
        !IsCompleteCpuMatrix(snapshot.cpu_matrix)) {
        return false;
    }
    const auto profile = static_cast<TargetEvidenceProfile>(snapshot.profile);
    if (profile != TargetEvidenceProfile::NativeIntelL0) return true;
    return HasFlag(snapshot, kTargetEvidenceSnapshotFlagVmxMatrix) &&
           IsCompleteVmxMatrix(snapshot.vmx_matrix);
}

u32 BuildManifestFlags(const TargetEvidenceSnapshot& snapshot) {
    u32 flags = 0U;
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagArtifacts)) {
        flags |= kTargetEvidenceFlagArtifactsVerified |
                 kTargetEvidenceFlagPdbMatched;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagSourceClean)) {
        flags |= kTargetEvidenceFlagSourceClean;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagSignature)) {
        flags |= kTargetEvidenceFlagSignatureVerified;
    }
    if (IsCapabilityComplete(snapshot)) {
        flags |= kTargetEvidenceFlagCapabilityComplete;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagHardwareEvidence)) {
        flags |= kTargetEvidenceFlagHardwareTarget;
    }
    if (IsOwnerEvidencePresent(snapshot) &&
        IsOwnerActionForProfile(
            static_cast<TargetEvidenceProfile>(snapshot.profile),
            snapshot.owner_gate)) {
        flags |= kTargetEvidenceFlagOwnerVerified;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagTimeSynchronized)) {
        flags |= kTargetEvidenceFlagTimeSynchronized;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagTelemetry)) {
        flags |= kTargetEvidenceFlagTelemetryComplete;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagRecoveryReady)) {
        flags |= kTargetEvidenceFlagRecoveryReady;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagNoCriticalFaults)) {
        flags |= kTargetEvidenceFlagNoCriticalFaults;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagKdConnected)) {
        flags |= kTargetEvidenceFlagKdConnected;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagDeviceProfiles)) {
        flags |= kTargetEvidenceFlagDeviceProfilesVerified;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagPerformance)) {
        flags |= kTargetEvidenceFlagPerformanceComparable;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagWarningsClear)) {
        flags |= kTargetEvidenceFlagWarningsClear;
    }
    return flags;
}

TargetEvidenceManifest MakeManifest(const TargetEvidenceSnapshot& snapshot) {
    TargetEvidenceManifest manifest{};
    manifest.size = sizeof(manifest);
    manifest.version = kTargetEvidenceContractVersion;
    manifest.profile = snapshot.profile;
    manifest.stage = snapshot.stage;
    manifest.verdict = snapshot.verdict;
    manifest.flags = BuildManifestFlags(snapshot);
    if (IsOwnerEvidencePresent(snapshot)) {
        manifest.owner_kind = snapshot.owner_observation.provider_owner;
        manifest.owner_state = snapshot.owner_observation.provider_state;
    }
    if (HasFlag(snapshot, kTargetEvidenceSnapshotFlagCpuMatrix)) {
        manifest.cpu_count = snapshot.cpu_matrix.expected_count;
        manifest.cpu_valid_count = snapshot.cpu_matrix.valid_count;
    }
    manifest.artifact_count = snapshot.artifact_count;
    manifest.warning_count = snapshot.warning_count;
    manifest.error_count = snapshot.error_count;
    manifest.generation = snapshot.generation;
    manifest.started_tsc = snapshot.started_tsc;
    manifest.ended_tsc = snapshot.ended_tsc;
    for (u32 index = 0U; index < 32U; ++index) {
        manifest.machine_id[index] = snapshot.machine_id[index];
        manifest.build_id[index] = snapshot.build_id[index];
        manifest.artifact_hash[index] = snapshot.artifact_hash[index];
        manifest.capability_hash[index] = snapshot.capability_hash[index];
        manifest.manifest_hash[index] = snapshot.manifest_hash[index];
    }
    return manifest;
}

void InitializeResult(TargetEvidenceSnapshotResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kTargetEvidenceSnapshotContractVersion;
    result->status = static_cast<u32>(TargetEvidenceSnapshotStatus::
                                          InvalidArgument);
    result->reason = static_cast<u32>(TargetEvidenceReason::InvalidRequest);
    result->writer_status = static_cast<u32>(
        TargetEvidenceWriterStatus::InvalidArgument);
}

void SetFailure(TargetEvidenceSnapshotResult* result,
                TargetEvidenceSnapshotStatus status,
                TargetEvidenceReason reason,
                TargetEvidenceWriterStatus writer_status =
                    TargetEvidenceWriterStatus::InvalidArgument) {
    result->status = static_cast<u32>(status);
    result->reason = static_cast<u32>(reason);
    result->writer_status = static_cast<u32>(writer_status);
}

TargetEvidenceReason ReasonForStatus(TargetEvidenceSnapshotStatus status) {
    switch (status) {
        case TargetEvidenceSnapshotStatus::CpuEvidenceInvalid:
        case TargetEvidenceSnapshotStatus::VmxEvidenceInvalid:
        case TargetEvidenceSnapshotStatus::CoverageIncomplete:
            return TargetEvidenceReason::CapabilityIncomplete;
        case TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid:
            return TargetEvidenceReason::OwnerUnverified;
        case TargetEvidenceSnapshotStatus::GenerationMismatch:
            return TargetEvidenceReason::GenerationMismatch;
        case TargetEvidenceSnapshotStatus::ProfileMismatch:
            return TargetEvidenceReason::ProfileMismatch;
        case TargetEvidenceSnapshotStatus::TimestampInvalid:
            return TargetEvidenceReason::TimeUnsynchronized;
        case TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing:
            return TargetEvidenceReason::ArtifactsUnverified;
        case TargetEvidenceSnapshotStatus::SignatureEvidenceMissing:
            return TargetEvidenceReason::SignatureUnverified;
        default:
            return TargetEvidenceReason::InvalidRequest;
    }
}

bool IsRequiredForPass(const TargetEvidenceSnapshot& snapshot, u32 flag) {
    return snapshot.verdict ==
               static_cast<u32>(TargetEvidenceVerdict::Pass) &&
           (RequiredTargetEvidenceFlags(
                static_cast<TargetEvidenceProfile>(snapshot.profile),
                static_cast<TargetEvidenceStage>(snapshot.stage)) &
            flag) != 0U;
}

}  // namespace

TargetEvidenceSnapshotStatus ValidateTargetEvidenceSnapshot(
    const TargetEvidenceSnapshot* snapshot, const CpuMatrixSample* cpu_samples,
    u32 cpu_sample_count, const VmxCapabilitySample* vmx_samples,
    u32 vmx_sample_count) {
    if (snapshot == nullptr ||
        !IsVersionedSizeValid(snapshot->version, snapshot->size,
                              sizeof(TargetEvidenceSnapshot)) ||
        (snapshot->flags & ~kTargetEvidenceSnapshotKnownFlagMask) != 0U ||
        snapshot->reserved != 0U || snapshot->reserved1 != 0U ||
        snapshot->reserved2 != 0U || !IsProfileValid(snapshot->profile) ||
        !IsStageValid(snapshot->stage) ||
        !IsVerdictValid(snapshot->verdict)) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }

    const auto profile = static_cast<TargetEvidenceProfile>(snapshot->profile);
    const auto stage = static_cast<TargetEvidenceStage>(snapshot->stage);
    const bool synthetic = profile == TargetEvidenceProfile::SyntheticLab;
    if (synthetic !=
            HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSynthetic) ||
        (synthetic &&
         HasFlag(*snapshot, kTargetEvidenceSnapshotFlagHardwareEvidence)) ||
        (HasFlag(*snapshot,
                 kTargetEvidenceSnapshotFlagAllowPrivateTestRoot) &&
         (!synthetic ||
          !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSignature)))) {
        return TargetEvidenceSnapshotStatus::ProfileMismatch;
    }

    const bool cpu_present =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagCpuMatrix);
    if (!cpu_present && cpu_sample_count != 0U) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (cpu_present) {
        if (cpu_sample_count != snapshot->cpu_matrix.sample_count ||
            (cpu_sample_count != 0U && cpu_samples == nullptr) ||
            !IsCpuMatrixSummaryValid(&snapshot->cpu_matrix)) {
            return TargetEvidenceSnapshotStatus::CpuEvidenceInvalid;
        }
        CpuMatrixSummary rebuilt{};
        if (!BuildCpuMatrixSummary(
                cpu_samples, cpu_sample_count, snapshot->cpu_matrix.expected_count,
                &rebuilt) ||
            !AreBytesEqual(&rebuilt, &snapshot->cpu_matrix,
                           sizeof(CpuMatrixSummary))) {
            return TargetEvidenceSnapshotStatus::CpuEvidenceInvalid;
        }
        if (snapshot->verdict == static_cast<u32>(TargetEvidenceVerdict::Pass) &&
            !IsCompleteCpuMatrix(snapshot->cpu_matrix)) {
            return TargetEvidenceSnapshotStatus::CoverageIncomplete;
        }
    } else if (!IsZeroBytes(&snapshot->cpu_matrix,
                            sizeof(snapshot->cpu_matrix))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }

    const bool vmx_present =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagVmxMatrix);
    if (!vmx_present && vmx_sample_count != 0U) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (vmx_present) {
        if (vmx_sample_count != snapshot->vmx_matrix.sample_count ||
            (vmx_sample_count != 0U && vmx_samples == nullptr) ||
            !IsVmxCapabilityMatrixValid(&snapshot->vmx_matrix)) {
            return TargetEvidenceSnapshotStatus::VmxEvidenceInvalid;
        }
        VmxCapabilityMatrix rebuilt{};
        if (!BuildVmxCapabilityMatrix(
                vmx_samples, vmx_sample_count, snapshot->vmx_matrix.expected_count,
                &rebuilt) ||
            !AreBytesEqual(&rebuilt, &snapshot->vmx_matrix,
                           sizeof(VmxCapabilityMatrix))) {
            return TargetEvidenceSnapshotStatus::VmxEvidenceInvalid;
        }
        if (snapshot->verdict == static_cast<u32>(TargetEvidenceVerdict::Pass) &&
            !IsCompleteVmxMatrix(snapshot->vmx_matrix)) {
            return TargetEvidenceSnapshotStatus::CoverageIncomplete;
        }
        if (snapshot->vmx_matrix.valid_count != 0U &&
            snapshot->vmx_matrix.generation != snapshot->generation) {
            return TargetEvidenceSnapshotStatus::GenerationMismatch;
        }
    } else if (!IsZeroBytes(&snapshot->vmx_matrix,
                            sizeof(snapshot->vmx_matrix))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }

    const bool owner_observation = HasFlag(
        *snapshot, kTargetEvidenceSnapshotFlagOwnerObservation);
    const bool owner_gate =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagOwnerGate);
    if (owner_observation != owner_gate) {
        return TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid;
    }
    if (owner_observation) {
        if (!IsOwnerObservationValid(&snapshot->owner_observation) ||
            !IsOwnerGateResultValid(&snapshot->owner_gate) ||
            snapshot->owner_observation.provider_owner !=
                snapshot->owner_gate.owner) {
            return TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid;
        }
        if (snapshot->owner_observation.generation != snapshot->generation ||
            snapshot->owner_gate.generation != snapshot->generation) {
            return TargetEvidenceSnapshotStatus::GenerationMismatch;
        }
        if (snapshot->verdict == static_cast<u32>(TargetEvidenceVerdict::Pass) &&
            static_cast<u32>(stage) >=
                static_cast<u32>(TargetEvidenceStage::Boot) &&
            !IsOwnerActionForProfile(profile, snapshot->owner_gate)) {
            return TargetEvidenceSnapshotStatus::ProfileMismatch;
        }
    } else if (!IsZeroBytes(&snapshot->owner_observation,
                            sizeof(snapshot->owner_observation)) ||
               !IsZeroBytes(&snapshot->owner_gate,
                            sizeof(snapshot->owner_gate))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }

    if (snapshot->ended_tsc != 0U &&
        snapshot->started_tsc > snapshot->ended_tsc) {
        return TargetEvidenceSnapshotStatus::TimestampInvalid;
    }
    if (snapshot->verdict == static_cast<u32>(TargetEvidenceVerdict::Pass) &&
        stage != TargetEvidenceStage::Inventory && snapshot->generation == 0U) {
        return TargetEvidenceSnapshotStatus::GenerationMismatch;
    }

    const bool artifacts =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagArtifacts);
    if (artifacts != (snapshot->artifact_count != 0U)) {
        return TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing;
    }
    if (artifacts && !IsDigestNonZero(snapshot->artifact_hash)) {
        return TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing;
    }
    if (!artifacts &&
        !IsZeroBytes(snapshot->artifact_hash, sizeof(snapshot->artifact_hash))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagArtifactsVerified) &&
        !artifacts) {
        return TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing;
    }

    const bool source_clean =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSourceClean);
    if (source_clean && !IsDigestNonZero(snapshot->build_id)) {
        return TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing;
    }
    if (!source_clean &&
        !IsZeroBytes(snapshot->build_id, sizeof(snapshot->build_id))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagSourceClean) &&
        !source_clean) {
        return TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing;
    }

    const bool signature =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSignature);
    if (signature && !IsTargetEvidenceSignatureResultValid(&snapshot->signature)) {
        return TargetEvidenceSnapshotStatus::SignatureEvidenceMissing;
    }
    if (!signature &&
        !IsZeroBytes(&snapshot->signature, sizeof(snapshot->signature))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (signature && !IsDigestNonZero(snapshot->manifest_hash)) {
        return TargetEvidenceSnapshotStatus::SignatureEvidenceMissing;
    }
    if (!signature &&
        !IsZeroBytes(snapshot->manifest_hash,
                     sizeof(snapshot->manifest_hash))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagSignatureVerified) &&
        !signature) {
        return TargetEvidenceSnapshotStatus::SignatureEvidenceMissing;
    }

    const bool hardware =
        HasFlag(*snapshot, kTargetEvidenceSnapshotFlagHardwareEvidence);
    if (hardware && !IsDigestNonZero(snapshot->machine_id)) {
        return TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing;
    }
    if (!hardware &&
        !IsZeroBytes(snapshot->machine_id, sizeof(snapshot->machine_id))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagCpuMatrix) &&
        !IsDigestNonZero(snapshot->capability_hash)) {
        return TargetEvidenceSnapshotStatus::CpuEvidenceInvalid;
    }
    if (!HasFlag(*snapshot, kTargetEvidenceSnapshotFlagCpuMatrix) &&
        !IsZeroBytes(snapshot->capability_hash,
                     sizeof(snapshot->capability_hash))) {
        return TargetEvidenceSnapshotStatus::InvalidArgument;
    }

    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagNoCriticalFaults) &&
        snapshot->error_count != 0U) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagWarningsClear) &&
        snapshot->warning_count != 0U) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagDeviceProfiles) &&
        (!hardware || !IsCapabilityComplete(*snapshot))) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagPerformance) &&
        (!HasFlag(*snapshot, kTargetEvidenceSnapshotFlagTimeSynchronized) ||
         !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagTelemetry))) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }

    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagCapabilityComplete) &&
        !IsCapabilityComplete(*snapshot)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagHardwareTarget) &&
        !hardware) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagOwnerVerified) &&
        (!owner_observation ||
         !IsOwnerActionForProfile(profile, snapshot->owner_gate))) {
        return TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagRecoveryReady) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagRecoveryReady)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagTimeSynchronized) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagTimeSynchronized)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagTelemetryComplete) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagTelemetry)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagNoCriticalFaults) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagNoCriticalFaults)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot,
                          kTargetEvidenceFlagDeviceProfilesVerified) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagDeviceProfiles)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagPerformanceComparable) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagPerformance)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    if (IsRequiredForPass(*snapshot, kTargetEvidenceFlagWarningsClear) &&
        !HasFlag(*snapshot, kTargetEvidenceSnapshotFlagWarningsClear)) {
        return TargetEvidenceSnapshotStatus::CoverageIncomplete;
    }
    return TargetEvidenceSnapshotStatus::Success;
}

bool IsTargetEvidenceSnapshotValid(
    const TargetEvidenceSnapshot* snapshot, const CpuMatrixSample* cpu_samples,
    u32 cpu_sample_count, const VmxCapabilitySample* vmx_samples,
    u32 vmx_sample_count) {
    return ValidateTargetEvidenceSnapshot(snapshot, cpu_samples,
                                          cpu_sample_count, vmx_samples,
                                          vmx_sample_count) ==
           TargetEvidenceSnapshotStatus::Success;
}

bool IsTargetEvidenceSnapshotResultValid(
    const TargetEvidenceSnapshotResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(TargetEvidenceSnapshotResult)) ||
        result->status > static_cast<u32>(
                             TargetEvidenceSnapshotStatus::WriterRejected) ||
        result->reason >
            static_cast<u32>(TargetEvidenceReason::OwnerStateInvalid) ||
        result->writer_status > static_cast<u32>(
                                    TargetEvidenceWriterStatus::
                                        GenerationInvalid) ||
        result->reserved != 0U) {
        return false;
    }
    const auto status = static_cast<TargetEvidenceSnapshotStatus>(
        result->status);
    if (status == TargetEvidenceSnapshotStatus::Success) {
        return result->reason == static_cast<u32>(TargetEvidenceReason::None) &&
               result->writer_status == static_cast<u32>(
                                             TargetEvidenceWriterStatus::Success) &&
               IsTargetEvidenceManifestValid(&result->manifest);
    }
    if (result->reason == static_cast<u32>(TargetEvidenceReason::None) ||
        result->writer_status == static_cast<u32>(
                                      TargetEvidenceWriterStatus::Success)) {
        return false;
    }
    return IsZeroBytes(&result->manifest, sizeof(result->manifest)) ||
           IsTargetEvidenceManifestValid(&result->manifest);
}

bool BuildTargetEvidenceManifestFromSnapshot(
    const TargetEvidenceSnapshot* snapshot, const CpuMatrixSample* cpu_samples,
    u32 cpu_sample_count, const VmxCapabilitySample* vmx_samples,
    u32 vmx_sample_count, TargetEvidenceSnapshotResult* result) {
    if (result == nullptr) return false;
    InitializeResult(result);
    const TargetEvidenceSnapshotStatus validation =
        ValidateTargetEvidenceSnapshot(snapshot, cpu_samples, cpu_sample_count,
                                       vmx_samples, vmx_sample_count);
    if (validation != TargetEvidenceSnapshotStatus::Success) {
        SetFailure(result, validation, ReasonForStatus(validation));
        return false;
    }

    const TargetEvidenceManifest candidate = MakeManifest(*snapshot);
    if (!IsTargetEvidenceManifestValid(&candidate)) {
        SetFailure(result, TargetEvidenceSnapshotStatus::WriterRejected,
                   TargetEvidenceReason::InvalidManifest);
        return false;
    }

    TargetEvidenceSignatureResult signature = snapshot->signature;
    if (!HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSignature)) {
        signature = {};
        signature.size = sizeof(signature);
        signature.version = kTargetEvidenceSignatureContractVersion;
        signature.status = static_cast<u32>(
            TargetEvidenceSignatureStatus::InvalidArgument);
    }
    TargetEvidenceManifestWriteRequest request{};
    request.size = sizeof(request);
    request.version = kTargetEvidenceWriterContractVersion;
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSynthetic)) {
        request.flags |= kTargetEvidenceWriterFlagAllowSynthetic;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagHardwareEvidence)) {
        request.flags |= kTargetEvidenceWriterFlagHardwareEvidence;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSourceClean)) {
        request.flags |= kTargetEvidenceWriterFlagSourceCleanObserved;
    }
    if (HasFlag(*snapshot, kTargetEvidenceSnapshotFlagSignature)) {
        request.flags |= kTargetEvidenceWriterFlagCommitSignature;
    }
    if (HasFlag(*snapshot,
                kTargetEvidenceSnapshotFlagAllowPrivateTestRoot)) {
        request.flags |= kTargetEvidenceWriterFlagAllowPrivateTestRoot;
    }
    request.candidate = candidate;
    request.signature = signature;

    TargetEvidenceManifestWriteResult writer_result{};
    if (!BuildTargetEvidenceManifest(&request, &writer_result) ||
        !IsTargetEvidenceManifestWriteResultValid(&writer_result)) {
        SetFailure(result, TargetEvidenceSnapshotStatus::WriterRejected,
                   TargetEvidenceReason::InvalidRequest);
        return false;
    }
    result->manifest = writer_result.manifest;
    result->writer_status = writer_result.status;
    if (writer_result.status != static_cast<u32>(
                                  TargetEvidenceWriterStatus::Success)) {
        result->status = static_cast<u32>(
            TargetEvidenceSnapshotStatus::WriterRejected);
        result->reason = writer_result.reason;
        return true;
    }
    result->status = static_cast<u32>(TargetEvidenceSnapshotStatus::Success);
    result->reason = static_cast<u32>(TargetEvidenceReason::None);
    return true;
}

const char* TargetEvidenceSnapshotStatusText(
    TargetEvidenceSnapshotStatus status) {
    switch (status) {
        case TargetEvidenceSnapshotStatus::Success:
            return "success";
        case TargetEvidenceSnapshotStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceSnapshotStatus::CpuEvidenceInvalid:
            return "cpu-evidence-invalid";
        case TargetEvidenceSnapshotStatus::VmxEvidenceInvalid:
            return "vmx-evidence-invalid";
        case TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid:
            return "owner-evidence-invalid";
        case TargetEvidenceSnapshotStatus::GenerationMismatch:
            return "generation-mismatch";
        case TargetEvidenceSnapshotStatus::CoverageIncomplete:
            return "coverage-incomplete";
        case TargetEvidenceSnapshotStatus::ProfileMismatch:
            return "profile-mismatch";
        case TargetEvidenceSnapshotStatus::TimestampInvalid:
            return "timestamp-invalid";
        case TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing:
            return "artifact-evidence-missing";
        case TargetEvidenceSnapshotStatus::SignatureEvidenceMissing:
            return "signature-evidence-missing";
        case TargetEvidenceSnapshotStatus::WriterRejected:
            return "writer-rejected";
        default:
            return "unknown";
    }
}

}  // namespace knhv
