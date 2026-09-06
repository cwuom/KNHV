#include "knhv_target_evidence.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTargetEvidenceContractVersion &&
           size >= required && size <= kTargetEvidenceMaxStructSize;
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

bool IsOwnerValid(u32 value) {
    return value <= static_cast<u32>(HvOwnerKindV2::SyntheticLab);
}

bool IsProviderStateValid(u32 value) {
    return value <= static_cast<u32>(HvProviderStateV2::Quarantined);
}

bool IsStatusValid(HvStatus status) {
    return static_cast<u32>(status) <= static_cast<u32>(HvStatus::Busy);
}

bool IsReasonValid(u32 value) {
    return value <= static_cast<u32>(TargetEvidenceReason::OwnerStateInvalid);
}

bool IsDigestNonZero(const u8* digest, u32 length) {
    if (digest == nullptr) return false;
    for (u32 index = 0; index < length; ++index) {
        if (digest[index] != 0U) return true;
    }
    return false;
}

bool IsStageAtLeast(TargetEvidenceStage stage, TargetEvidenceStage minimum) {
    return static_cast<u32>(stage) >= static_cast<u32>(minimum);
}

bool IsOwnerStateUsable(TargetEvidenceProfile profile, u32 owner,
                        u32 state) {
    const auto owner_kind = static_cast<HvOwnerKindV2>(owner);
    const auto provider_state = static_cast<HvProviderStateV2>(state);
    switch (profile) {
        case TargetEvidenceProfile::NativeIntelL0:
            return owner_kind == HvOwnerKindV2::KnhvBootL0 &&
                   provider_state == HvProviderStateV2::Active;
        case TargetEvidenceProfile::WhpManaged:
            return owner_kind == HvOwnerKindV2::WhpManaged &&
                   (provider_state == HvProviderStateV2::Available ||
                    provider_state == HvProviderStateV2::Active);
        case TargetEvidenceProfile::ExternalL0:
            return owner_kind == HvOwnerKindV2::ExternalL0 &&
                   provider_state != HvProviderStateV2::Unknown &&
                   provider_state != HvProviderStateV2::Blocked &&
                   provider_state != HvProviderStateV2::Quarantined;
        case TargetEvidenceProfile::SyntheticLab:
            return owner_kind == HvOwnerKindV2::SyntheticLab &&
                   (provider_state == HvProviderStateV2::Available ||
                    provider_state == HvProviderStateV2::Active);
        default:
            return false;
    }
}

void InitializeResult(TargetEvidenceGateResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kTargetEvidenceContractVersion;
    result->status = HvStatus::InvalidParameter;
    result->reason = static_cast<u32>(TargetEvidenceReason::InvalidRequest);
}

void SetResult(TargetEvidenceGateResult* result, HvStatus status,
               TargetEvidenceReason reason, u32 missing_flags, u32 observed,
               u64 generation) {
    result->status = status;
    result->reason = static_cast<u32>(reason);
    result->missing_flags = missing_flags;
    result->observed_flags = observed;
    result->generation = generation;
}

TargetEvidenceReason MissingReason(u32 missing_flags) {
    if ((missing_flags & kTargetEvidenceFlagSourceClean) != 0U) {
        return TargetEvidenceReason::SourceDirty;
    }
    if ((missing_flags & kTargetEvidenceFlagArtifactsVerified) != 0U ||
        (missing_flags & kTargetEvidenceFlagPdbMatched) != 0U) {
        return TargetEvidenceReason::ArtifactsUnverified;
    }
    if ((missing_flags & kTargetEvidenceFlagSignatureVerified) != 0U) {
        return TargetEvidenceReason::SignatureUnverified;
    }
    if ((missing_flags & kTargetEvidenceFlagCapabilityComplete) != 0U) {
        return TargetEvidenceReason::CapabilityIncomplete;
    }
    if ((missing_flags & kTargetEvidenceFlagOwnerVerified) != 0U) {
        return TargetEvidenceReason::OwnerUnverified;
    }
    if ((missing_flags & kTargetEvidenceFlagTimeSynchronized) != 0U) {
        return TargetEvidenceReason::TimeUnsynchronized;
    }
    if ((missing_flags & kTargetEvidenceFlagTelemetryComplete) != 0U) {
        return TargetEvidenceReason::TelemetryIncomplete;
    }
    if ((missing_flags & kTargetEvidenceFlagRecoveryReady) != 0U) {
        return TargetEvidenceReason::RecoveryUnavailable;
    }
    if ((missing_flags & kTargetEvidenceFlagNoCriticalFaults) != 0U) {
        return TargetEvidenceReason::CriticalFault;
    }
    if ((missing_flags & kTargetEvidenceFlagHardwareTarget) != 0U ||
        (missing_flags & kTargetEvidenceFlagKdConnected) != 0U) {
        return TargetEvidenceReason::CapabilityIncomplete;
    }
    if ((missing_flags & kTargetEvidenceFlagDeviceProfilesVerified) != 0U) {
        return TargetEvidenceReason::DeviceProfileMissing;
    }
    if ((missing_flags & kTargetEvidenceFlagPerformanceComparable) != 0U) {
        return TargetEvidenceReason::PerformanceNotComparable;
    }
    if ((missing_flags & kTargetEvidenceFlagWarningsClear) != 0U) {
        return TargetEvidenceReason::WarningsPresent;
    }
    return TargetEvidenceReason::MissingFlags;
}

HvStatus StatusForVerdict(TargetEvidenceVerdict verdict) {
    switch (verdict) {
        case TargetEvidenceVerdict::RolledBack:
            return HvStatus::RecoveryRequired;
        case TargetEvidenceVerdict::Blocked:
            return HvStatus::HardwareOwnerConflict;
        case TargetEvidenceVerdict::Fail:
            return HvStatus::CapabilityMismatch;
        case TargetEvidenceVerdict::NotComparable:
            return HvStatus::CapabilityMismatch;
        case TargetEvidenceVerdict::Ready:
        case TargetEvidenceVerdict::Running:
            return HvStatus::Busy;
        default:
            return HvStatus::NestedUnavailable;
    }
}

}  // namespace

bool IsTargetEvidenceManifestValid(const TargetEvidenceManifest* manifest) {
    if (manifest == nullptr ||
        !IsVersionedSizeValid(manifest->version, manifest->size,
                              sizeof(TargetEvidenceManifest)) ||
        !IsProfileValid(manifest->profile) || !IsStageValid(manifest->stage) ||
        !IsVerdictValid(manifest->verdict) || !IsOwnerValid(manifest->owner_kind) ||
        !IsProviderStateValid(manifest->owner_state) ||
        (manifest->flags & ~kTargetEvidenceKnownFlagMask) != 0U ||
        manifest->reserved0 != 0U || manifest->reserved[0] != 0U ||
        manifest->reserved[1] != 0U || manifest->reserved[2] != 0U ||
        manifest->reserved[3] != 0U ||
        manifest->cpu_count > kTargetEvidenceMaxProcessors ||
        manifest->cpu_valid_count > manifest->cpu_count ||
        manifest->artifact_count > kTargetEvidenceMaxArtifacts ||
        (manifest->ended_tsc != 0U &&
         manifest->started_tsc > manifest->ended_tsc)) {
        return false;
    }

    const auto profile = static_cast<TargetEvidenceProfile>(manifest->profile);
    const auto stage = static_cast<TargetEvidenceStage>(manifest->stage);
    const auto verdict = static_cast<TargetEvidenceVerdict>(manifest->verdict);
    const auto owner = static_cast<HvOwnerKindV2>(manifest->owner_kind);
    const auto owner_state = static_cast<HvProviderStateV2>(
        manifest->owner_state);
    if ((manifest->flags & kTargetEvidenceFlagPdbMatched) != 0U &&
        (manifest->flags & kTargetEvidenceFlagArtifactsVerified) == 0U) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagArtifactsVerified) != 0U &&
        (manifest->artifact_count == 0U ||
         !IsDigestNonZero(manifest->artifact_hash, 32U))) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagCapabilityComplete) != 0U &&
        (manifest->cpu_count == 0U ||
         manifest->cpu_valid_count != manifest->cpu_count ||
         !IsDigestNonZero(manifest->capability_hash, 32U))) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagOwnerVerified) != 0U &&
        (!IsOwnerStateUsable(profile, manifest->owner_kind,
                             manifest->owner_state) ||
         manifest->generation == 0U)) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagSignatureVerified) != 0U &&
        !IsDigestNonZero(manifest->manifest_hash, 32U)) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagSourceClean) != 0U &&
        !IsDigestNonZero(manifest->build_id, 32U)) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagHardwareTarget) != 0U &&
        !IsDigestNonZero(manifest->machine_id, 32U)) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagDeviceProfilesVerified) != 0U &&
        ((manifest->flags & kTargetEvidenceFlagHardwareTarget) == 0U ||
         (manifest->flags & kTargetEvidenceFlagCapabilityComplete) == 0U)) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagPerformanceComparable) != 0U &&
        ((manifest->flags & kTargetEvidenceFlagTimeSynchronized) == 0U ||
         (manifest->flags & kTargetEvidenceFlagTelemetryComplete) == 0U)) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagWarningsClear) != 0U &&
        manifest->warning_count != 0U) {
        return false;
    }
    if ((manifest->flags & kTargetEvidenceFlagNoCriticalFaults) != 0U &&
        manifest->error_count != 0U) {
        return false;
    }
    if (manifest->verdict == static_cast<u32>(TargetEvidenceVerdict::Pass) &&
        manifest->error_count != 0U) {
        return false;
    }
    if (owner == HvOwnerKindV2::Unknown &&
        owner_state != HvProviderStateV2::Unknown) {
        return false;
    }
    if (stage != TargetEvidenceStage::Inventory &&
        verdict == TargetEvidenceVerdict::Pass && manifest->generation == 0U) {
        return false;
    }
    return true;
}

bool IsTargetEvidenceGateRequestValid(
    const TargetEvidenceGateRequest* request) {
    return request != nullptr &&
           IsVersionedSizeValid(request->version, request->size,
                                sizeof(TargetEvidenceGateRequest)) &&
           IsProfileValid(request->profile) && IsStageValid(request->minimum_stage) &&
           (request->required_flags & ~kTargetEvidenceKnownFlagMask) == 0U &&
           request->reserved == 0U;
}

bool IsTargetEvidenceGateResultValid(const TargetEvidenceGateResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(TargetEvidenceGateResult)) ||
        !IsStatusValid(result->status) || !IsReasonValid(result->reason) ||
        (result->missing_flags & ~kTargetEvidenceKnownFlagMask) != 0U ||
        (result->observed_flags & ~kTargetEvidenceKnownFlagMask) != 0U ||
        result->reserved != 0U) {
        return false;
    }
    if (result->status == HvStatus::Success) {
        return result->reason == static_cast<u32>(TargetEvidenceReason::None) &&
               result->missing_flags == 0U && result->generation != 0U;
    }
    return result->reason != static_cast<u32>(TargetEvidenceReason::None);
}

u32 RequiredTargetEvidenceFlags(TargetEvidenceProfile profile,
                                TargetEvidenceStage stage) {
    if (!IsProfileValid(static_cast<u32>(profile)) ||
        !IsStageValid(static_cast<u32>(stage))) {
        return 0U;
    }
    u32 flags = 0U;
    if (stage == TargetEvidenceStage::Inventory ||
        stage == TargetEvidenceStage::Preflight) {
        return flags;
    }
    switch (profile) {
        case TargetEvidenceProfile::NativeIntelL0:
            flags = kTargetEvidenceFlagCapabilityComplete |
                    kTargetEvidenceFlagHardwareTarget;
            break;
        case TargetEvidenceProfile::WhpManaged:
            flags = kTargetEvidenceFlagCapabilityComplete;
            break;
        case TargetEvidenceProfile::ExternalL0:
            flags = kTargetEvidenceFlagOwnerVerified;
            break;
        case TargetEvidenceProfile::SyntheticLab:
            flags = kTargetEvidenceFlagOwnerVerified;
            break;
        default:
            return 0U;
    }
    if (IsStageAtLeast(stage, TargetEvidenceStage::Boot)) {
        flags |= kTargetEvidenceFlagOwnerVerified |
                 kTargetEvidenceFlagRecoveryReady;
        if (profile == TargetEvidenceProfile::NativeIntelL0) {
            flags |= kTargetEvidenceFlagKdConnected;
        }
    }
    if (IsStageAtLeast(stage, TargetEvidenceStage::Nested)) {
        flags |= kTargetEvidenceFlagTimeSynchronized |
                 kTargetEvidenceFlagTelemetryComplete |
                 kTargetEvidenceFlagNoCriticalFaults;
    }
    if (IsStageAtLeast(stage, TargetEvidenceStage::Boot)) {
        flags |= kTargetEvidenceFlagArtifactsVerified |
                 kTargetEvidenceFlagPdbMatched;
    }
    if (IsStageAtLeast(stage, TargetEvidenceStage::Device) &&
        profile == TargetEvidenceProfile::NativeIntelL0) {
        flags |= kTargetEvidenceFlagDeviceProfilesVerified;
    }
    if (IsStageAtLeast(stage, TargetEvidenceStage::Performance)) {
        flags |= kTargetEvidenceFlagPerformanceComparable;
    }
    if (IsStageAtLeast(stage, TargetEvidenceStage::Release)) {
        flags |= kTargetEvidenceFlagSourceClean |
                 kTargetEvidenceFlagSignatureVerified |
                 kTargetEvidenceFlagWarningsClear;
    }
    return flags;
}

bool EvaluateTargetEvidenceGate(const TargetEvidenceManifest* manifest,
                                const TargetEvidenceGateRequest* request,
                                TargetEvidenceGateResult* result) {
    if (result == nullptr) return false;
    InitializeResult(result);
    if (!IsTargetEvidenceGateRequestValid(request)) return false;
    if (!IsTargetEvidenceManifestValid(manifest)) {
        result->reason = static_cast<u32>(TargetEvidenceReason::InvalidManifest);
        return false;
    }

    const auto requested_profile =
        static_cast<TargetEvidenceProfile>(request->profile);
    const auto manifest_profile =
        static_cast<TargetEvidenceProfile>(manifest->profile);
    const auto manifest_stage =
        static_cast<TargetEvidenceStage>(manifest->stage);
    const auto manifest_verdict =
        static_cast<TargetEvidenceVerdict>(manifest->verdict);
    result->observed_flags = manifest->flags;
    result->generation = manifest->generation;
    if (manifest_profile != requested_profile) {
        SetResult(result, HvStatus::IncompatibleProvider,
                  TargetEvidenceReason::ProfileMismatch, 0U, manifest->flags,
                  manifest->generation);
        return true;
    }
    if (manifest_stage <
        static_cast<TargetEvidenceStage>(request->minimum_stage)) {
        SetResult(result, HvStatus::CapabilityMismatch,
                  TargetEvidenceReason::StageIncomplete, 0U, manifest->flags,
                  manifest->generation);
        return true;
    }
    if (request->expected_generation != 0U &&
        request->expected_generation != manifest->generation) {
        SetResult(result, HvStatus::BootHandoffFailed,
                  TargetEvidenceReason::GenerationMismatch, 0U,
                  manifest->flags, manifest->generation);
        return true;
    }
    if (manifest_verdict != TargetEvidenceVerdict::Pass) {
        const TargetEvidenceReason reason =
            manifest_verdict == TargetEvidenceVerdict::NotComparable
                ? TargetEvidenceReason::PerformanceNotComparable
                : TargetEvidenceReason::VerdictNotPass;
        SetResult(result, StatusForVerdict(manifest_verdict), reason, 0U,
                  manifest->flags, manifest->generation);
        return true;
    }

    const u32 required_flags =
        request->required_flags != 0U
            ? request->required_flags
            : RequiredTargetEvidenceFlags(requested_profile,
                                           static_cast<TargetEvidenceStage>(
                                               request->minimum_stage));
    const u32 missing_flags = required_flags & ~manifest->flags;
    if (missing_flags != 0U) {
        SetResult(result, HvStatus::CapabilityMismatch,
                  MissingReason(missing_flags), missing_flags, manifest->flags,
                  manifest->generation);
        return true;
    }
    if ((required_flags & kTargetEvidenceFlagOwnerVerified) != 0U &&
        !IsOwnerStateUsable(requested_profile, manifest->owner_kind,
                            manifest->owner_state)) {
        SetResult(result, HvStatus::HardwareOwnerConflict,
                  TargetEvidenceReason::OwnerStateInvalid, 0U, manifest->flags,
                  manifest->generation);
        return true;
    }
    if (manifest->generation == 0U) {
        SetResult(result, HvStatus::BootHandoffFailed,
                  TargetEvidenceReason::GenerationMismatch, 0U,
                  manifest->flags, manifest->generation);
        return true;
    }
    SetResult(result, HvStatus::Success, TargetEvidenceReason::None, 0U,
              manifest->flags, manifest->generation);
    return true;
}

const char* TargetEvidenceProfileText(TargetEvidenceProfile profile) {
    switch (profile) {
        case TargetEvidenceProfile::NativeIntelL0:
            return "native-intel-l0";
        case TargetEvidenceProfile::WhpManaged:
            return "whp-managed";
        case TargetEvidenceProfile::ExternalL0:
            return "external-l0";
        case TargetEvidenceProfile::SyntheticLab:
            return "synthetic-lab";
        default:
            return "unknown";
    }
}

const char* TargetEvidenceStageText(TargetEvidenceStage stage) {
    switch (stage) {
        case TargetEvidenceStage::Inventory:
            return "inventory";
        case TargetEvidenceStage::Preflight:
            return "preflight";
        case TargetEvidenceStage::Capability:
            return "capability";
        case TargetEvidenceStage::Boot:
            return "boot";
        case TargetEvidenceStage::Nested:
            return "nested";
        case TargetEvidenceStage::Device:
            return "device";
        case TargetEvidenceStage::Performance:
            return "performance";
        case TargetEvidenceStage::Reliability:
            return "reliability";
        case TargetEvidenceStage::Release:
            return "release";
        default:
            return "invalid";
    }
}

const char* TargetEvidenceVerdictText(TargetEvidenceVerdict verdict) {
    switch (verdict) {
        case TargetEvidenceVerdict::NotStarted:
            return "not-started";
        case TargetEvidenceVerdict::Ready:
            return "ready";
        case TargetEvidenceVerdict::Running:
            return "running";
        case TargetEvidenceVerdict::Pass:
            return "pass";
        case TargetEvidenceVerdict::Fail:
            return "fail";
        case TargetEvidenceVerdict::Blocked:
            return "blocked";
        case TargetEvidenceVerdict::NotRun:
            return "not-run";
        case TargetEvidenceVerdict::RolledBack:
            return "rolled-back";
        case TargetEvidenceVerdict::NotComparable:
            return "not-comparable";
        default:
            return "invalid";
    }
}

const char* TargetEvidenceReasonText(TargetEvidenceReason reason) {
    switch (reason) {
        case TargetEvidenceReason::None:
            return "none";
        case TargetEvidenceReason::InvalidManifest:
            return "invalid-manifest";
        case TargetEvidenceReason::InvalidRequest:
            return "invalid-request";
        case TargetEvidenceReason::ProfileMismatch:
            return "profile-mismatch";
        case TargetEvidenceReason::StageIncomplete:
            return "stage-incomplete";
        case TargetEvidenceReason::VerdictNotPass:
            return "verdict-not-pass";
        case TargetEvidenceReason::GenerationMismatch:
            return "generation-mismatch";
        case TargetEvidenceReason::MissingFlags:
            return "missing-flags";
        case TargetEvidenceReason::OwnerUnverified:
            return "owner-unverified";
        case TargetEvidenceReason::CapabilityIncomplete:
            return "capability-incomplete";
        case TargetEvidenceReason::ArtifactsUnverified:
            return "artifacts-unverified";
        case TargetEvidenceReason::SignatureUnverified:
            return "signature-unverified";
        case TargetEvidenceReason::TimeUnsynchronized:
            return "time-unsynchronized";
        case TargetEvidenceReason::TelemetryIncomplete:
            return "telemetry-incomplete";
        case TargetEvidenceReason::RecoveryUnavailable:
            return "recovery-unavailable";
        case TargetEvidenceReason::CriticalFault:
            return "critical-fault";
        case TargetEvidenceReason::CpuIncomplete:
            return "cpu-incomplete";
        case TargetEvidenceReason::HashMissing:
            return "hash-missing";
        case TargetEvidenceReason::DeviceProfileMissing:
            return "device-profile-missing";
        case TargetEvidenceReason::PerformanceNotComparable:
            return "performance-not-comparable";
        case TargetEvidenceReason::SourceDirty:
            return "source-dirty";
        case TargetEvidenceReason::WarningsPresent:
            return "warnings-present";
        case TargetEvidenceReason::OwnerStateInvalid:
            return "owner-state-invalid";
        default:
            return "invalid";
    }
}

}  // namespace knhv
