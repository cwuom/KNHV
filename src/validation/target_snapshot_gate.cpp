#include <cstring>

#include "knhv_target_snapshot_gate.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTargetEvidenceSnapshotGateContractVersion &&
           size >= required && size <= kTargetEvidenceSnapshotMaxStructSize;
}

bool IsStatusValid(u32 value) {
    return value <= static_cast<u32>(
                         TargetEvidenceSnapshotGateStatus::GateInvalid);
}

bool IsSnapshotStatusValid(u32 value) {
    return value <= static_cast<u32>(
                         TargetEvidenceSnapshotStatus::WriterRejected);
}

bool IsZeroManifest(const TargetEvidenceManifest& manifest) {
    const auto* bytes = reinterpret_cast<const u8*>(&manifest);
    for (u32 index = 0U; index < sizeof(manifest); ++index) {
        if (bytes[index] != 0U) return false;
    }
    return true;
}

void InitializeGate(TargetEvidenceGateResult* gate) {
    *gate = {};
    gate->size = sizeof(*gate);
    gate->version = kTargetEvidenceContractVersion;
    gate->status = HvStatus::InvalidParameter;
    gate->reason = static_cast<u32>(TargetEvidenceReason::InvalidRequest);
}

void InitializeResult(TargetEvidenceSnapshotGateResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kTargetEvidenceSnapshotGateContractVersion;
    result->status = static_cast<u32>(
        TargetEvidenceSnapshotGateStatus::InvalidArgument);
    result->snapshot_status = static_cast<u32>(
        TargetEvidenceSnapshotStatus::InvalidArgument);
    InitializeGate(&result->gate);
}

bool IsSnapshotValidationFailure(TargetEvidenceSnapshotStatus status) {
    return status != TargetEvidenceSnapshotStatus::WriterRejected;
}

}  // namespace

TargetEvidenceSnapshotGateStatus EvaluateTargetEvidenceSnapshotGate(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count,
    const TargetEvidenceGateRequest* request,
    TargetEvidenceSnapshotGateResult* result) {
    if (result == nullptr) {
        return TargetEvidenceSnapshotGateStatus::InvalidArgument;
    }
    InitializeResult(result);
    if (!IsTargetEvidenceGateRequestValid(request)) {
        return TargetEvidenceSnapshotGateStatus::InvalidArgument;
    }

    TargetEvidenceSnapshotResult snapshot_result{};
    const bool materialized = BuildTargetEvidenceManifestFromSnapshot(
        snapshot, cpu_samples, cpu_sample_count, vmx_samples,
        vmx_sample_count, &snapshot_result);
    if (!IsTargetEvidenceSnapshotResultValid(&snapshot_result)) {
        result->snapshot_status = static_cast<u32>(
            TargetEvidenceSnapshotStatus::InvalidArgument);
        result->status = static_cast<u32>(
            TargetEvidenceSnapshotGateStatus::ManifestInvalid);
        return TargetEvidenceSnapshotGateStatus::ManifestInvalid;
    }
    result->snapshot_status = snapshot_result.status;
    const auto snapshot_status = static_cast<TargetEvidenceSnapshotStatus>(
        snapshot_result.status);
    if (!materialized || snapshot_status !=
                                    TargetEvidenceSnapshotStatus::Success) {
        result->status = static_cast<u32>(
            IsSnapshotValidationFailure(snapshot_status)
                ? TargetEvidenceSnapshotGateStatus::SnapshotInvalid
                : TargetEvidenceSnapshotGateStatus::ManifestInvalid);
        return static_cast<TargetEvidenceSnapshotGateStatus>(
            result->status);
    }
    result->manifest = snapshot_result.manifest;
    if (!IsTargetEvidenceManifestValid(&result->manifest)) {
        result->manifest = {};
        result->status = static_cast<u32>(
            TargetEvidenceSnapshotGateStatus::ManifestInvalid);
        return TargetEvidenceSnapshotGateStatus::ManifestInvalid;
    }

    TargetEvidenceGateResult gate{};
    if (!EvaluateTargetEvidenceGate(&result->manifest, request, &gate) ||
        !IsTargetEvidenceGateResultValid(&gate)) {
        result->manifest = {};
        result->status = static_cast<u32>(
            TargetEvidenceSnapshotGateStatus::GateInvalid);
        return TargetEvidenceSnapshotGateStatus::GateInvalid;
    }
    result->gate = gate;
    result->status = static_cast<u32>(
        gate.status == HvStatus::Success
            ? TargetEvidenceSnapshotGateStatus::Success
            : TargetEvidenceSnapshotGateStatus::GateBlocked);
    return static_cast<TargetEvidenceSnapshotGateStatus>(result->status);
}

bool IsTargetEvidenceSnapshotGateResultValid(
    const TargetEvidenceSnapshotGateResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(TargetEvidenceSnapshotGateResult)) ||
        !IsStatusValid(result->status) ||
        !IsSnapshotStatusValid(result->snapshot_status) ||
        result->reserved0 != 0U || result->reserved1 != 0U ||
        !IsTargetEvidenceGateResultValid(&result->gate)) {
        return false;
    }
    const auto status = static_cast<TargetEvidenceSnapshotGateStatus>(
        result->status);
    const auto gate_success = result->gate.status == HvStatus::Success;
    const bool manifest_valid = IsTargetEvidenceManifestValid(&result->manifest);
    const bool manifest_zero = IsZeroManifest(result->manifest);
    if (status == TargetEvidenceSnapshotGateStatus::Success) {
        return result->snapshot_status ==
                   static_cast<u32>(TargetEvidenceSnapshotStatus::Success) &&
               gate_success && manifest_valid;
    }
    if (status == TargetEvidenceSnapshotGateStatus::GateBlocked) {
        return result->snapshot_status ==
                   static_cast<u32>(TargetEvidenceSnapshotStatus::Success) &&
               !gate_success && manifest_valid;
    }
    if (status == TargetEvidenceSnapshotGateStatus::SnapshotInvalid) {
        return result->snapshot_status !=
                   static_cast<u32>(TargetEvidenceSnapshotStatus::Success) &&
               !gate_success && manifest_zero;
    }
    if (status == TargetEvidenceSnapshotGateStatus::ManifestInvalid ||
        status == TargetEvidenceSnapshotGateStatus::GateInvalid) {
        return !gate_success && manifest_zero;
    }
    return !gate_success && manifest_zero;
}

const char* TargetEvidenceSnapshotGateStatusText(
    TargetEvidenceSnapshotGateStatus status) {
    switch (status) {
        case TargetEvidenceSnapshotGateStatus::Success:
            return "success";
        case TargetEvidenceSnapshotGateStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceSnapshotGateStatus::SnapshotInvalid:
            return "snapshot-invalid";
        case TargetEvidenceSnapshotGateStatus::ManifestInvalid:
            return "manifest-invalid";
        case TargetEvidenceSnapshotGateStatus::GateBlocked:
            return "gate-blocked";
        case TargetEvidenceSnapshotGateStatus::GateInvalid:
            return "gate-invalid";
        default:
            return "unknown";
    }
}

}  // namespace knhv
