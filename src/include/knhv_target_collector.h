#pragma once

#include "knhv_target_snapshot.h"

namespace knhv {

// this binding records which collector produced an already verified snapshot
constexpr u32 kTargetEvidenceCollectorContractVersion = 1U;
constexpr u32 kTargetEvidenceCollectorMaxStructSize = 4096U;

constexpr u32 kTargetEvidenceCollectorFlagSynthetic = 1U << 0;
constexpr u32 kTargetEvidenceCollectorFlagHardware = 1U << 1;
constexpr u32 kTargetEvidenceCollectorFlagSourceClean = 1U << 2;
constexpr u32 kTargetEvidenceCollectorFlagSignature = 1U << 3;
constexpr u32 kTargetEvidenceCollectorFlagFirstFailure = 1U << 4;
constexpr u32 kTargetEvidenceCollectorFlagDigestVerified = 1U << 5;
constexpr u32 kTargetEvidenceCollectorKnownFlagMask = (1U << 6) - 1U;

enum class TargetEvidenceCollectorStatus : u32 {
    Success = 0,
    InvalidArgument = 1,
    SnapshotInvalid = 2,
    DigestMissing = 3,
    DigestMismatch = 4,
    IdentityMissing = 5,
    GenerationMismatch = 6,
    TimestampMismatch = 7,
    CoverageMismatch = 8,
    FlagMismatch = 9,
    SignatureMismatch = 10,
    FirstFailureMismatch = 11,
};

enum class TargetEvidenceCollectorReason : u32 {
    None = 0,
    InvalidRequest = 1,
    Snapshot = 2,
    DigestMissing = 3,
    DigestMismatch = 4,
    IdentityMissing = 5,
    GenerationMismatch = 6,
    TimestampMismatch = 7,
    CoverageMismatch = 8,
    FlagMismatch = 9,
    SignatureMismatch = 10,
    FirstFailureMismatch = 11,
};

#pragma pack(push, 8)

struct TargetEvidenceCollectorBinding {
    u32 size;
    u32 version;
    u32 flags;
    u32 reserved;
    u64 capture_id;
    u64 generation;
    u64 started_tsc;
    u64 ended_tsc;
    u32 cpu_sample_count;
    u32 vmx_sample_count;
    u32 first_failure_code;
    u32 reserved1;
    u8 collector_id[32];
    u8 package_digest[32];
    u8 collector_build_id[32];
    u8 artifact_hash[32];
    TargetEvidenceSignatureResult signature;
};

struct TargetEvidenceCollectorBindingResult {
    u32 size;
    u32 version;
    u32 status;
    u32 reason;
    u32 reserved0;
    u32 reserved1;
    u64 generation;
    u64 capture_id;
};

#pragma pack(pop)

bool IsTargetEvidenceCollectorBindingValid(
    const TargetEvidenceCollectorBinding* binding);
bool IsTargetEvidenceCollectorBindingResultValid(
    const TargetEvidenceCollectorBindingResult* result);
TargetEvidenceCollectorStatus ValidateTargetEvidenceCollectorBinding(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count,
    const u8* verified_package_digest,
    const TargetEvidenceCollectorBinding* binding,
    TargetEvidenceCollectorBindingResult* result);
const char* TargetEvidenceCollectorStatusText(
    TargetEvidenceCollectorStatus status);
const char* TargetEvidenceCollectorReasonText(
    TargetEvidenceCollectorReason reason);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceCollectorBinding) == 216,
              "target evidence collector binding ABI changed");
static_assert(sizeof(knhv::TargetEvidenceCollectorBindingResult) == 40,
              "target evidence collector result ABI changed");
#endif
