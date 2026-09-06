#pragma once

#include "knhv_target_snapshot.h"

namespace knhv {

// this adapter binds decoded target evidence to the existing release gate
constexpr u32 kTargetEvidenceSnapshotGateContractVersion = 1U;

enum class TargetEvidenceSnapshotGateStatus : u32 {
    Success = 0,
    InvalidArgument = 1,
    SnapshotInvalid = 2,
    ManifestInvalid = 3,
    GateBlocked = 4,
    GateInvalid = 5,
};

#pragma pack(push, 8)
struct TargetEvidenceSnapshotGateResult {
    u32 size;
    u32 version;
    u32 status;
    u32 snapshot_status;
    u32 reserved0;
    u32 reserved1;
    TargetEvidenceGateResult gate;
    TargetEvidenceManifest manifest;
};
#pragma pack(pop)

TargetEvidenceSnapshotGateStatus EvaluateTargetEvidenceSnapshotGate(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count,
    const TargetEvidenceGateRequest* request,
    TargetEvidenceSnapshotGateResult* result);
bool IsTargetEvidenceSnapshotGateResultValid(
    const TargetEvidenceSnapshotGateResult* result);
const char* TargetEvidenceSnapshotGateStatusText(
    TargetEvidenceSnapshotGateStatus status);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceSnapshotGateResult) == 320,
              "target evidence snapshot gate result ABI changed");
#endif
