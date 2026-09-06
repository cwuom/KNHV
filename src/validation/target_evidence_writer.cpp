#include "knhv_target_evidence_writer.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTargetEvidenceWriterContractVersion &&
           size >= required && size <= kTargetEvidenceWriterMaxStructSize;
}

bool IsStatusValid(u32 value) {
    return value <= static_cast<u32>(
                         TargetEvidenceWriterStatus::GenerationInvalid);
}

bool IsReasonValid(u32 value) {
    return value <= static_cast<u32>(TargetEvidenceReason::OwnerStateInvalid);
}

bool IsSyntheticProfile(const TargetEvidenceManifest& manifest) {
    return manifest.profile ==
           static_cast<u32>(TargetEvidenceProfile::SyntheticLab);
}

bool IsHardwareProfile(const TargetEvidenceManifest& manifest) {
    return manifest.profile ==
           static_cast<u32>(TargetEvidenceProfile::NativeIntelL0);
}

bool IsAtLeastCapability(const TargetEvidenceManifest& manifest) {
    return manifest.stage >=
           static_cast<u32>(TargetEvidenceStage::Capability);
}

bool IsRelease(const TargetEvidenceManifest& manifest) {
    return manifest.stage == static_cast<u32>(TargetEvidenceStage::Release);
}

bool HasFlag(const TargetEvidenceManifest& manifest, u32 flag) {
    return (manifest.flags & flag) != 0U;
}

bool HasWriterFlag(const TargetEvidenceManifestWriteRequest& request,
                   u32 flag) {
    return (request.flags & flag) != 0U;
}

void InitializeResult(TargetEvidenceManifestWriteResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kTargetEvidenceWriterContractVersion;
    result->status = static_cast<u32>(
        TargetEvidenceWriterStatus::InvalidArgument);
    result->reason = static_cast<u32>(TargetEvidenceReason::InvalidRequest);
}

bool IsTrusted(const TargetEvidenceSignatureResult& signature) {
    return signature.status == static_cast<u32>(
                                   TargetEvidenceSignatureStatus::Trusted) &&
           signature.wintrust_status == 0U;
}

bool IsAcceptedPrivateRoot(const TargetEvidenceSignatureResult& signature) {
    return signature.status == static_cast<u32>(
                                   TargetEvidenceSignatureStatus::
                                       PrivateTestRoot) &&
           signature.wintrust_status != 0U &&
           (signature.result_flags &
            kTargetEvidenceSignatureResultPrivateRootAccepted) != 0U;
}

void SetFailure(TargetEvidenceManifestWriteResult* result,
                TargetEvidenceWriterStatus status, TargetEvidenceReason reason) {
    result->status = static_cast<u32>(status);
    result->reason = static_cast<u32>(reason);
}

bool IsZeroManifest(const TargetEvidenceManifest& manifest) {
    const u8* bytes = reinterpret_cast<const u8*>(&manifest);
    for (u32 index = 0U; index < sizeof(manifest); ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

}  // namespace

bool IsTargetEvidenceManifestWriteRequestValid(
    const TargetEvidenceManifestWriteRequest* request) {
    return request != nullptr &&
           IsVersionedSizeValid(request->version, request->size,
                                sizeof(TargetEvidenceManifestWriteRequest)) &&
           (request->flags & ~kTargetEvidenceWriterKnownFlagMask) == 0U &&
           request->reserved == 0U &&
           IsTargetEvidenceManifestValid(&request->candidate) &&
           IsTargetEvidenceSignatureResultValid(&request->signature);
}

bool IsTargetEvidenceManifestWriteResultValid(
    const TargetEvidenceManifestWriteResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(TargetEvidenceManifestWriteResult)) ||
        !IsStatusValid(result->status) || !IsReasonValid(result->reason) ||
        result->reserved != 0U) {
        return false;
    }
    const auto status =
        static_cast<TargetEvidenceWriterStatus>(result->status);
    if (status == TargetEvidenceWriterStatus::Success) {
        return result->reason == static_cast<u32>(TargetEvidenceReason::None) &&
               IsTargetEvidenceManifestValid(&result->manifest);
    }
    if (result->reason == static_cast<u32>(TargetEvidenceReason::None)) {
        return false;
    }
    return IsZeroManifest(result->manifest) ||
           IsTargetEvidenceManifestValid(&result->manifest);
}

bool BuildTargetEvidenceManifest(
    const TargetEvidenceManifestWriteRequest* request,
    TargetEvidenceManifestWriteResult* result) {
    if (result == nullptr) return false;
    InitializeResult(result);
    if (!IsTargetEvidenceManifestWriteRequestValid(request)) return false;
    result->manifest = request->candidate;

    const TargetEvidenceManifest& candidate = request->candidate;
    const bool synthetic = IsSyntheticProfile(candidate);
    const bool hardware = HasFlag(candidate, kTargetEvidenceFlagHardwareTarget);
    if (synthetic) {
        if (!HasWriterFlag(*request, kTargetEvidenceWriterFlagAllowSynthetic) ||
            HasWriterFlag(*request, kTargetEvidenceWriterFlagHardwareEvidence) ||
            hardware) {
            SetFailure(result, TargetEvidenceWriterStatus::
                                      SyntheticPolicyViolation,
                       TargetEvidenceReason::InvalidRequest);
            return true;
        }
    } else if (HasWriterFlag(*request, kTargetEvidenceWriterFlagAllowSynthetic)) {
        SetFailure(result, TargetEvidenceWriterStatus::
                                  SyntheticPolicyViolation,
                   TargetEvidenceReason::InvalidRequest);
        return true;
    }

    if (hardware &&
        !HasWriterFlag(*request,
                       kTargetEvidenceWriterFlagHardwareEvidence)) {
        SetFailure(result, TargetEvidenceWriterStatus::
                                  HardwareEvidenceRequired,
                   TargetEvidenceReason::CapabilityIncomplete);
        return true;
    }
    if (!synthetic && IsHardwareProfile(candidate) &&
        IsAtLeastCapability(candidate) &&
        !HasWriterFlag(*request, kTargetEvidenceWriterFlagHardwareEvidence)) {
        SetFailure(result, TargetEvidenceWriterStatus::
                                  HardwareEvidenceRequired,
                   TargetEvidenceReason::CapabilityIncomplete);
        return true;
    }
    if (HasFlag(candidate, kTargetEvidenceFlagSourceClean) &&
        !HasWriterFlag(*request,
                       kTargetEvidenceWriterFlagSourceCleanObserved)) {
        SetFailure(result, TargetEvidenceWriterStatus::SourceDirty,
                   TargetEvidenceReason::SourceDirty);
        return true;
    }

    const bool signature_flag =
        HasFlag(candidate, kTargetEvidenceFlagSignatureVerified);
    const bool commit_signature =
        HasWriterFlag(*request, kTargetEvidenceWriterFlagCommitSignature);
    const bool trusted = IsTrusted(request->signature);
    const bool private_root = IsAcceptedPrivateRoot(request->signature);
    const bool private_root_allowed =
        HasWriterFlag(*request,
                      kTargetEvidenceWriterFlagAllowPrivateTestRoot);
    const bool signature_is_usable =
        trusted || (synthetic && private_root && private_root_allowed);

    if (signature_flag || commit_signature ||
        (IsRelease(candidate) && !synthetic)) {
        if (!signature_is_usable) {
            const auto signature_status =
                static_cast<TargetEvidenceSignatureStatus>(
                    request->signature.status);
            SetFailure(result,
                       signature_status ==
                               TargetEvidenceSignatureStatus::InvalidArgument
                           ? TargetEvidenceWriterStatus::SignatureRequired
                           : TargetEvidenceWriterStatus::SignatureUntrusted,
                       TargetEvidenceReason::SignatureUnverified);
            return true;
        }
    }
    if (commit_signature) {
        if (!signature_is_usable) {
            SetFailure(result, TargetEvidenceWriterStatus::SignatureRequired,
                       TargetEvidenceReason::SignatureUnverified);
            return true;
        }
        result->manifest.flags |= kTargetEvidenceFlagSignatureVerified;
    }

    if (result->manifest.generation == 0U &&
        result->manifest.stage !=
            static_cast<u32>(TargetEvidenceStage::Inventory) &&
        result->manifest.verdict ==
            static_cast<u32>(TargetEvidenceVerdict::Pass)) {
        SetFailure(result, TargetEvidenceWriterStatus::GenerationInvalid,
                   TargetEvidenceReason::GenerationMismatch);
        return true;
    }
    if (!IsTargetEvidenceManifestValid(&result->manifest)) {
        SetFailure(result, TargetEvidenceWriterStatus::InvalidManifest,
                   TargetEvidenceReason::InvalidManifest);
        return true;
    }
    result->status = static_cast<u32>(TargetEvidenceWriterStatus::Success);
    result->reason = static_cast<u32>(TargetEvidenceReason::None);
    return true;
}

const char* TargetEvidenceWriterStatusText(
    TargetEvidenceWriterStatus status) {
    switch (status) {
        case TargetEvidenceWriterStatus::Success:
            return "success";
        case TargetEvidenceWriterStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceWriterStatus::InvalidManifest:
            return "invalid-manifest";
        case TargetEvidenceWriterStatus::SignatureRequired:
            return "signature-required";
        case TargetEvidenceWriterStatus::SignatureUntrusted:
            return "signature-untrusted";
        case TargetEvidenceWriterStatus::HardwareEvidenceRequired:
            return "hardware-evidence-required";
        case TargetEvidenceWriterStatus::SyntheticPolicyViolation:
            return "synthetic-policy-violation";
        case TargetEvidenceWriterStatus::SourceDirty:
            return "source-dirty";
        case TargetEvidenceWriterStatus::GenerationInvalid:
            return "generation-invalid";
        default:
            return "unknown";
    }
}

}  // namespace knhv
