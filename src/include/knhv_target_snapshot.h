#pragma once

#include "knhv_cpu_matrix.h"
#include "knhv_owner_observation.h"
#include "knhv_target_evidence_signature.h"
#include "knhv_target_evidence_writer.h"
#include "knhv_vmx_capability.h"

namespace knhv {

// this record describes observations supplied by a target-side collector
constexpr u32 kTargetEvidenceSnapshotContractVersion = 1U;
constexpr u32 kTargetEvidenceSnapshotMaxStructSize = 4096U;

constexpr u32 kTargetEvidenceSnapshotFlagCpuMatrix = 1U << 0;
constexpr u32 kTargetEvidenceSnapshotFlagVmxMatrix = 1U << 1;
constexpr u32 kTargetEvidenceSnapshotFlagOwnerObservation = 1U << 2;
constexpr u32 kTargetEvidenceSnapshotFlagOwnerGate = 1U << 3;
constexpr u32 kTargetEvidenceSnapshotFlagHardwareEvidence = 1U << 4;
constexpr u32 kTargetEvidenceSnapshotFlagArtifacts = 1U << 5;
constexpr u32 kTargetEvidenceSnapshotFlagSourceClean = 1U << 6;
constexpr u32 kTargetEvidenceSnapshotFlagTimeSynchronized = 1U << 7;
constexpr u32 kTargetEvidenceSnapshotFlagTelemetry = 1U << 8;
constexpr u32 kTargetEvidenceSnapshotFlagRecoveryReady = 1U << 9;
constexpr u32 kTargetEvidenceSnapshotFlagSignature = 1U << 10;
constexpr u32 kTargetEvidenceSnapshotFlagSynthetic = 1U << 11;
constexpr u32 kTargetEvidenceSnapshotFlagKdConnected = 1U << 12;
constexpr u32 kTargetEvidenceSnapshotFlagDeviceProfiles = 1U << 13;
constexpr u32 kTargetEvidenceSnapshotFlagPerformance = 1U << 14;
constexpr u32 kTargetEvidenceSnapshotFlagNoCriticalFaults = 1U << 15;
constexpr u32 kTargetEvidenceSnapshotFlagWarningsClear = 1U << 16;
constexpr u32 kTargetEvidenceSnapshotFlagAllowPrivateTestRoot = 1U << 17;
constexpr u32 kTargetEvidenceSnapshotKnownFlagMask = (1U << 18) - 1U;

enum class TargetEvidenceSnapshotStatus : u32 {
    Success = 0,
    InvalidArgument = 1,
    CpuEvidenceInvalid = 2,
    VmxEvidenceInvalid = 3,
    OwnerEvidenceInvalid = 4,
    GenerationMismatch = 5,
    CoverageIncomplete = 6,
    ProfileMismatch = 7,
    TimestampInvalid = 8,
    ArtifactEvidenceMissing = 9,
    SignatureEvidenceMissing = 10,
    WriterRejected = 11,
};

#pragma pack(push, 8)

struct TargetEvidenceSnapshot {
    u32 size;
    u32 version;
    u32 flags;
    u32 reserved;
    u32 profile;
    u32 stage;
    u32 verdict;
    u32 reserved1;
    u32 warning_count;
    u32 error_count;
    u32 artifact_count;
    u32 reserved2;
    u64 generation;
    u64 started_tsc;
    u64 ended_tsc;
    CpuMatrixSummary cpu_matrix;
    VmxCapabilityMatrix vmx_matrix;
    OwnerObservation owner_observation;
    OwnerGateResult owner_gate;
    TargetEvidenceSignatureResult signature;
    u8 machine_id[32];
    u8 build_id[32];
    u8 artifact_hash[32];
    u8 capability_hash[32];
    u8 manifest_hash[32];
};

struct TargetEvidenceSnapshotResult {
    u32 size;
    u32 version;
    u32 status;
    u32 reason;
    u32 writer_status;
    u32 reserved;
    TargetEvidenceManifest manifest;
};

#pragma pack(pop)

TargetEvidenceSnapshotStatus ValidateTargetEvidenceSnapshot(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count);
bool IsTargetEvidenceSnapshotValid(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count);
bool IsTargetEvidenceSnapshotResultValid(
    const TargetEvidenceSnapshotResult* result);
bool BuildTargetEvidenceManifestFromSnapshot(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count,
    TargetEvidenceSnapshotResult* result);
const char* TargetEvidenceSnapshotStatusText(
    TargetEvidenceSnapshotStatus status);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceSnapshot) == 544,
              "target evidence snapshot ABI changed");
static_assert(sizeof(knhv::TargetEvidenceSnapshotResult) == 280,
              "target evidence snapshot result ABI changed");
#endif
