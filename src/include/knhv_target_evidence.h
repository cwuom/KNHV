#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kTargetEvidenceContractVersion = 1U;
constexpr u32 kTargetEvidenceMaxStructSize = 4096U;
constexpr u32 kTargetEvidenceMaxProcessors = 4096U;
constexpr u32 kTargetEvidenceMaxArtifacts = 65535U;

enum class TargetEvidenceProfile : u32 {
    Unknown = 0,
    NativeIntelL0 = 1,
    WhpManaged = 2,
    ExternalL0 = 3,
    SyntheticLab = 4,
};

enum class TargetEvidenceStage : u32 {
    Inventory = 0,
    Preflight = 1,
    Capability = 2,
    Boot = 3,
    Nested = 4,
    Device = 5,
    Performance = 6,
    Reliability = 7,
    Release = 8,
};

enum class TargetEvidenceVerdict : u32 {
    NotStarted = 0,
    Ready = 1,
    Running = 2,
    Pass = 3,
    Fail = 4,
    Blocked = 5,
    NotRun = 6,
    RolledBack = 7,
    NotComparable = 8,
};

constexpr u32 kTargetEvidenceFlagSourceClean = 1U << 0;
constexpr u32 kTargetEvidenceFlagArtifactsVerified = 1U << 1;
constexpr u32 kTargetEvidenceFlagSignatureVerified = 1U << 2;
constexpr u32 kTargetEvidenceFlagPdbMatched = 1U << 3;
constexpr u32 kTargetEvidenceFlagCapabilityComplete = 1U << 4;
constexpr u32 kTargetEvidenceFlagOwnerVerified = 1U << 5;
constexpr u32 kTargetEvidenceFlagTimeSynchronized = 1U << 6;
constexpr u32 kTargetEvidenceFlagTelemetryComplete = 1U << 7;
constexpr u32 kTargetEvidenceFlagRecoveryReady = 1U << 8;
constexpr u32 kTargetEvidenceFlagNoCriticalFaults = 1U << 9;
constexpr u32 kTargetEvidenceFlagHardwareTarget = 1U << 10;
constexpr u32 kTargetEvidenceFlagKdConnected = 1U << 11;
constexpr u32 kTargetEvidenceFlagDeviceProfilesVerified = 1U << 12;
constexpr u32 kTargetEvidenceFlagPerformanceComparable = 1U << 13;
constexpr u32 kTargetEvidenceFlagWarningsClear = 1U << 14;
constexpr u32 kTargetEvidenceKnownFlagMask = (1U << 15) - 1U;

enum class TargetEvidenceReason : u32 {
    None = 0,
    InvalidManifest = 1,
    InvalidRequest = 2,
    ProfileMismatch = 3,
    StageIncomplete = 4,
    VerdictNotPass = 5,
    GenerationMismatch = 6,
    MissingFlags = 7,
    OwnerUnverified = 8,
    CapabilityIncomplete = 9,
    ArtifactsUnverified = 10,
    SignatureUnverified = 11,
    TimeUnsynchronized = 12,
    TelemetryIncomplete = 13,
    RecoveryUnavailable = 14,
    CriticalFault = 15,
    CpuIncomplete = 16,
    HashMissing = 17,
    DeviceProfileMissing = 18,
    PerformanceNotComparable = 19,
    SourceDirty = 20,
    WarningsPresent = 21,
    OwnerStateInvalid = 22,
};

#pragma pack(push, 8)

struct TargetEvidenceManifest {
    u32 size;
    u32 version;
    u32 profile;
    u32 stage;
    u32 verdict;
    u32 flags;
    u32 owner_kind;
    u32 owner_state;
    u32 cpu_count;
    u32 cpu_valid_count;
    u32 artifact_count;
    u32 warning_count;
    u32 error_count;
    u32 reserved0;
    u64 generation;
    u64 started_tsc;
    u64 ended_tsc;
    u8 machine_id[32];
    u8 build_id[32];
    u8 artifact_hash[32];
    u8 capability_hash[32];
    u8 manifest_hash[32];
    u32 reserved[4];
};

struct TargetEvidenceGateRequest {
    u32 size;
    u32 version;
    u32 profile;
    u32 minimum_stage;
    u32 required_flags;
    u32 reserved;
    u64 expected_generation;
};

struct TargetEvidenceGateResult {
    u32 size;
    u32 version;
    HvStatus status;
    u32 reason;
    u32 missing_flags;
    u32 observed_flags;
    u32 reserved;
    u64 generation;
};

#pragma pack(pop)

bool IsTargetEvidenceManifestValid(const TargetEvidenceManifest* manifest);
bool IsTargetEvidenceGateRequestValid(
    const TargetEvidenceGateRequest* request);
bool IsTargetEvidenceGateResultValid(const TargetEvidenceGateResult* result);
u32 RequiredTargetEvidenceFlags(TargetEvidenceProfile profile,
                                TargetEvidenceStage stage);
bool EvaluateTargetEvidenceGate(const TargetEvidenceManifest* manifest,
                                const TargetEvidenceGateRequest* request,
                                TargetEvidenceGateResult* result);

const char* TargetEvidenceProfileText(TargetEvidenceProfile profile);
const char* TargetEvidenceStageText(TargetEvidenceStage stage);
const char* TargetEvidenceVerdictText(TargetEvidenceVerdict verdict);
const char* TargetEvidenceReasonText(TargetEvidenceReason reason);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceManifest) == 256,
              "target evidence manifest ABI changed");
static_assert(sizeof(knhv::TargetEvidenceGateRequest) == 32,
              "target evidence request ABI changed");
static_assert(sizeof(knhv::TargetEvidenceGateResult) == 40,
              "target evidence result ABI changed");
#endif
