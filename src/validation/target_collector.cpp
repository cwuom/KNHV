#include <cstring>

#include "knhv_target_collector.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTargetEvidenceCollectorContractVersion &&
           size >= required && size <= kTargetEvidenceCollectorMaxStructSize;
}

bool IsStatusValid(u32 value) {
    return value <= static_cast<u32>(
                         TargetEvidenceCollectorStatus::FirstFailureMismatch);
}

bool IsReasonValid(u32 value) {
    return value <= static_cast<u32>(
                         TargetEvidenceCollectorReason::FirstFailureMismatch);
}

bool IsZeroBytes(const void* value, u32 size) {
    if (value == nullptr) return false;
    const auto* bytes = reinterpret_cast<const u8*>(value);
    for (u32 index = 0U; index < size; ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

bool IsNonZeroBytes(const void* value, u32 size) {
    if (value == nullptr) return false;
    const auto* bytes = reinterpret_cast<const u8*>(value);
    for (u32 index = 0U; index < size; ++index) {
        if (bytes[index] != 0U) return true;
    }
    return false;
}

bool AreBytesEqual(const void* left, const void* right, u32 size) {
    if (left == nullptr || right == nullptr) return false;
    const auto* left_bytes = reinterpret_cast<const u8*>(left);
    const auto* right_bytes = reinterpret_cast<const u8*>(right);
    for (u32 index = 0U; index < size; ++index) {
        if (left_bytes[index] != right_bytes[index]) return false;
    }
    return true;
}

void InitializeResult(TargetEvidenceCollectorBindingResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kTargetEvidenceCollectorContractVersion;
    result->status = static_cast<u32>(
        TargetEvidenceCollectorStatus::InvalidArgument);
    result->reason = static_cast<u32>(
        TargetEvidenceCollectorReason::InvalidRequest);
}

void SetFailure(TargetEvidenceCollectorBindingResult* result,
                TargetEvidenceCollectorStatus status,
                TargetEvidenceCollectorReason reason) {
    result->status = static_cast<u32>(status);
    result->reason = static_cast<u32>(reason);
    result->generation = 0U;
    result->capture_id = 0U;
}

u32 ExpectedFlags(const TargetEvidenceSnapshot& snapshot,
                  const TargetEvidenceCollectorBinding& binding) {
    u32 flags = kTargetEvidenceCollectorFlagDigestVerified;
    if (snapshot.profile ==
        static_cast<u32>(TargetEvidenceProfile::SyntheticLab)) {
        flags |= kTargetEvidenceCollectorFlagSynthetic;
    }
    if ((snapshot.flags & kTargetEvidenceSnapshotFlagHardwareEvidence) != 0U) {
        flags |= kTargetEvidenceCollectorFlagHardware;
    }
    if ((snapshot.flags & kTargetEvidenceSnapshotFlagSourceClean) != 0U) {
        flags |= kTargetEvidenceCollectorFlagSourceClean;
    }
    if ((snapshot.flags & kTargetEvidenceSnapshotFlagSignature) != 0U) {
        flags |= kTargetEvidenceCollectorFlagSignature;
    }
    if (binding.first_failure_code != 0U) {
        flags |= kTargetEvidenceCollectorFlagFirstFailure;
    }
    return flags;
}

}  // namespace

bool IsTargetEvidenceCollectorBindingValid(
    const TargetEvidenceCollectorBinding* binding) {
    if (binding == nullptr ||
        !IsVersionedSizeValid(binding->version, binding->size,
                              sizeof(TargetEvidenceCollectorBinding)) ||
        (binding->flags & ~kTargetEvidenceCollectorKnownFlagMask) != 0U ||
        binding->reserved != 0U || binding->reserved1 != 0U ||
        binding->capture_id == 0U ||
        (binding->flags & kTargetEvidenceCollectorFlagDigestVerified) == 0U ||
        !IsNonZeroBytes(binding->collector_id,
                        sizeof(binding->collector_id)) ||
        !IsNonZeroBytes(binding->collector_build_id,
                        sizeof(binding->collector_build_id)) ||
        !IsNonZeroBytes(binding->package_digest,
                        sizeof(binding->package_digest)) ||
        binding->cpu_sample_count > kCpuMatrixMaxProcessors ||
        binding->vmx_sample_count > kVmxCapabilityMaxProcessors ||
        (binding->ended_tsc != 0U &&
         binding->started_tsc > binding->ended_tsc)) {
        return false;
    }

    const bool failure_flag =
        (binding->flags & kTargetEvidenceCollectorFlagFirstFailure) != 0U;
    if (failure_flag != (binding->first_failure_code != 0U)) return false;

    const bool signature_flag =
        (binding->flags & kTargetEvidenceCollectorFlagSignature) != 0U;
    if (signature_flag) {
        if (!IsTargetEvidenceSignatureResultValid(&binding->signature)) {
            return false;
        }
    } else if (!IsZeroBytes(&binding->signature, sizeof(binding->signature))) {
        return false;
    }
    return true;
}

bool IsTargetEvidenceCollectorBindingResultValid(
    const TargetEvidenceCollectorBindingResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(TargetEvidenceCollectorBindingResult)) ||
        !IsStatusValid(result->status) || !IsReasonValid(result->reason) ||
        result->reserved0 != 0U || result->reserved1 != 0U) {
        return false;
    }
    const auto status = static_cast<TargetEvidenceCollectorStatus>(
        result->status);
    if (status == TargetEvidenceCollectorStatus::Success) {
        return result->reason ==
                   static_cast<u32>(TargetEvidenceCollectorReason::None) &&
               result->capture_id != 0U;
    }
    return result->reason !=
               static_cast<u32>(TargetEvidenceCollectorReason::None) &&
           result->capture_id == 0U && result->generation == 0U;
}

TargetEvidenceCollectorStatus ValidateTargetEvidenceCollectorBinding(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count,
    const u8* verified_package_digest,
    const TargetEvidenceCollectorBinding* binding,
    TargetEvidenceCollectorBindingResult* result) {
    if (result == nullptr) {
        return TargetEvidenceCollectorStatus::InvalidArgument;
    }
    InitializeResult(result);
    if (snapshot == nullptr || verified_package_digest == nullptr ||
        binding == nullptr) {
        return TargetEvidenceCollectorStatus::InvalidArgument;
    }
    if (!IsVersionedSizeValid(binding->version, binding->size,
                              sizeof(TargetEvidenceCollectorBinding)) ||
        (binding->flags & ~kTargetEvidenceCollectorKnownFlagMask) != 0U ||
        binding->reserved != 0U || binding->reserved1 != 0U) {
        return TargetEvidenceCollectorStatus::InvalidArgument;
    }
    if (!IsNonZeroBytes(binding->collector_id,
                        sizeof(binding->collector_id)) ||
        !IsNonZeroBytes(binding->collector_build_id,
                        sizeof(binding->collector_build_id))) {
        SetFailure(result, TargetEvidenceCollectorStatus::IdentityMissing,
                   TargetEvidenceCollectorReason::IdentityMissing);
        return TargetEvidenceCollectorStatus::IdentityMissing;
    }
    if (!IsNonZeroBytes(binding->package_digest,
                        sizeof(binding->package_digest))) {
        SetFailure(result, TargetEvidenceCollectorStatus::DigestMissing,
                   TargetEvidenceCollectorReason::DigestMissing);
        return TargetEvidenceCollectorStatus::DigestMissing;
    }
    if (!IsTargetEvidenceCollectorBindingValid(binding)) {
        return TargetEvidenceCollectorStatus::InvalidArgument;
    }

    const auto snapshot_status = ValidateTargetEvidenceSnapshot(
        snapshot, cpu_samples, cpu_sample_count, vmx_samples,
        vmx_sample_count);
    if (snapshot_status != TargetEvidenceSnapshotStatus::Success) {
        SetFailure(result, TargetEvidenceCollectorStatus::SnapshotInvalid,
                   TargetEvidenceCollectorReason::Snapshot);
        return TargetEvidenceCollectorStatus::SnapshotInvalid;
    }
    if (!IsNonZeroBytes(verified_package_digest, 32U)) {
        SetFailure(result, TargetEvidenceCollectorStatus::DigestMissing,
                   TargetEvidenceCollectorReason::DigestMissing);
        return TargetEvidenceCollectorStatus::DigestMissing;
    }
    if (!AreBytesEqual(verified_package_digest, binding->package_digest,
                       32U)) {
        SetFailure(result, TargetEvidenceCollectorStatus::DigestMismatch,
                   TargetEvidenceCollectorReason::DigestMismatch);
        return TargetEvidenceCollectorStatus::DigestMismatch;
    }
    if (binding->generation != snapshot->generation) {
        SetFailure(result, TargetEvidenceCollectorStatus::GenerationMismatch,
                   TargetEvidenceCollectorReason::GenerationMismatch);
        return TargetEvidenceCollectorStatus::GenerationMismatch;
    }
    if (binding->started_tsc != snapshot->started_tsc ||
        binding->ended_tsc != snapshot->ended_tsc) {
        SetFailure(result, TargetEvidenceCollectorStatus::TimestampMismatch,
                   TargetEvidenceCollectorReason::TimestampMismatch);
        return TargetEvidenceCollectorStatus::TimestampMismatch;
    }
    if (binding->cpu_sample_count != cpu_sample_count ||
        binding->vmx_sample_count != vmx_sample_count) {
        SetFailure(result, TargetEvidenceCollectorStatus::CoverageMismatch,
                   TargetEvidenceCollectorReason::CoverageMismatch);
        return TargetEvidenceCollectorStatus::CoverageMismatch;
    }
    if (binding->flags != ExpectedFlags(*snapshot, *binding)) {
        SetFailure(result, TargetEvidenceCollectorStatus::FlagMismatch,
                   TargetEvidenceCollectorReason::FlagMismatch);
        return TargetEvidenceCollectorStatus::FlagMismatch;
    }

    const bool artifacts =
        (snapshot->flags & kTargetEvidenceSnapshotFlagArtifacts) != 0U;
    if (artifacts) {
        if (!AreBytesEqual(binding->artifact_hash, snapshot->artifact_hash,
                           sizeof(binding->artifact_hash))) {
            SetFailure(result, TargetEvidenceCollectorStatus::DigestMismatch,
                       TargetEvidenceCollectorReason::DigestMismatch);
            return TargetEvidenceCollectorStatus::DigestMismatch;
        }
    } else if (!IsZeroBytes(binding->artifact_hash,
                            sizeof(binding->artifact_hash))) {
        SetFailure(result, TargetEvidenceCollectorStatus::FlagMismatch,
                   TargetEvidenceCollectorReason::FlagMismatch);
        return TargetEvidenceCollectorStatus::FlagMismatch;
    }

    const bool signature =
        (snapshot->flags & kTargetEvidenceSnapshotFlagSignature) != 0U;
    if (signature) {
        if (!AreBytesEqual(&binding->signature, &snapshot->signature,
                           sizeof(binding->signature))) {
            SetFailure(result, TargetEvidenceCollectorStatus::SignatureMismatch,
                       TargetEvidenceCollectorReason::SignatureMismatch);
            return TargetEvidenceCollectorStatus::SignatureMismatch;
        }
    } else if (!IsZeroBytes(&binding->signature, sizeof(binding->signature))) {
        SetFailure(result, TargetEvidenceCollectorStatus::FlagMismatch,
                   TargetEvidenceCollectorReason::FlagMismatch);
        return TargetEvidenceCollectorStatus::FlagMismatch;
    }

    if (snapshot->verdict == static_cast<u32>(TargetEvidenceVerdict::Pass) &&
        binding->first_failure_code != 0U) {
        SetFailure(result, TargetEvidenceCollectorStatus::FirstFailureMismatch,
                   TargetEvidenceCollectorReason::FirstFailureMismatch);
        return TargetEvidenceCollectorStatus::FirstFailureMismatch;
    }

    result->status = static_cast<u32>(TargetEvidenceCollectorStatus::Success);
    result->reason = static_cast<u32>(TargetEvidenceCollectorReason::None);
    result->generation = binding->generation;
    result->capture_id = binding->capture_id;
    return TargetEvidenceCollectorStatus::Success;
}

const char* TargetEvidenceCollectorStatusText(
    TargetEvidenceCollectorStatus status) {
    switch (status) {
        case TargetEvidenceCollectorStatus::Success:
            return "success";
        case TargetEvidenceCollectorStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceCollectorStatus::SnapshotInvalid:
            return "snapshot-invalid";
        case TargetEvidenceCollectorStatus::DigestMissing:
            return "digest-missing";
        case TargetEvidenceCollectorStatus::DigestMismatch:
            return "digest-mismatch";
        case TargetEvidenceCollectorStatus::IdentityMissing:
            return "identity-missing";
        case TargetEvidenceCollectorStatus::GenerationMismatch:
            return "generation-mismatch";
        case TargetEvidenceCollectorStatus::TimestampMismatch:
            return "timestamp-mismatch";
        case TargetEvidenceCollectorStatus::CoverageMismatch:
            return "coverage-mismatch";
        case TargetEvidenceCollectorStatus::FlagMismatch:
            return "flag-mismatch";
        case TargetEvidenceCollectorStatus::SignatureMismatch:
            return "signature-mismatch";
        case TargetEvidenceCollectorStatus::FirstFailureMismatch:
            return "first-failure-mismatch";
        default:
            return "unknown";
    }
}

const char* TargetEvidenceCollectorReasonText(
    TargetEvidenceCollectorReason reason) {
    switch (reason) {
        case TargetEvidenceCollectorReason::None:
            return "none";
        case TargetEvidenceCollectorReason::InvalidRequest:
            return "invalid-request";
        case TargetEvidenceCollectorReason::Snapshot:
            return "snapshot";
        case TargetEvidenceCollectorReason::DigestMissing:
            return "digest-missing";
        case TargetEvidenceCollectorReason::DigestMismatch:
            return "digest-mismatch";
        case TargetEvidenceCollectorReason::IdentityMissing:
            return "identity-missing";
        case TargetEvidenceCollectorReason::GenerationMismatch:
            return "generation-mismatch";
        case TargetEvidenceCollectorReason::TimestampMismatch:
            return "timestamp-mismatch";
        case TargetEvidenceCollectorReason::CoverageMismatch:
            return "coverage-mismatch";
        case TargetEvidenceCollectorReason::FlagMismatch:
            return "flag-mismatch";
        case TargetEvidenceCollectorReason::SignatureMismatch:
            return "signature-mismatch";
        case TargetEvidenceCollectorReason::FirstFailureMismatch:
            return "first-failure-mismatch";
        default:
            return "unknown";
    }
}

}  // namespace knhv
