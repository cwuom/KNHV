#pragma once

#include "knhv_target_evidence.h"
#include "knhv_target_evidence_signature.h"

namespace knhv {

// this writer accepts an already collected snapshot and never reads hardware
constexpr u32 kTargetEvidenceWriterContractVersion = 1U;
constexpr u32 kTargetEvidenceWriterMaxStructSize = 4096U;

constexpr u32 kTargetEvidenceWriterFlagAllowSynthetic = 1U << 0;
constexpr u32 kTargetEvidenceWriterFlagAllowPrivateTestRoot = 1U << 1;
constexpr u32 kTargetEvidenceWriterFlagHardwareEvidence = 1U << 2;
constexpr u32 kTargetEvidenceWriterFlagSourceCleanObserved = 1U << 3;
constexpr u32 kTargetEvidenceWriterFlagCommitSignature = 1U << 4;
constexpr u32 kTargetEvidenceWriterKnownFlagMask = (1U << 5) - 1U;

enum class TargetEvidenceWriterStatus : u32 {
    Success = 0,
    InvalidArgument = 1,
    InvalidManifest = 2,
    SignatureRequired = 3,
    SignatureUntrusted = 4,
    HardwareEvidenceRequired = 5,
    SyntheticPolicyViolation = 6,
    SourceDirty = 7,
    GenerationInvalid = 8,
};

#pragma pack(push, 8)

struct TargetEvidenceManifestWriteRequest {
    u32 size;
    u32 version;
    u32 flags;
    u32 reserved;
    TargetEvidenceManifest candidate;
    TargetEvidenceSignatureResult signature;
};

struct TargetEvidenceManifestWriteResult {
    u32 size;
    u32 version;
    u32 status;
    u32 reason;
    u32 reserved;
    TargetEvidenceManifest manifest;
};

#pragma pack(pop)

bool IsTargetEvidenceManifestWriteRequestValid(
    const TargetEvidenceManifestWriteRequest* request);
bool IsTargetEvidenceManifestWriteResultValid(
    const TargetEvidenceManifestWriteResult* result);
bool BuildTargetEvidenceManifest(
    const TargetEvidenceManifestWriteRequest* request,
    TargetEvidenceManifestWriteResult* result);
const char* TargetEvidenceWriterStatusText(TargetEvidenceWriterStatus status);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceManifestWriteRequest) == 296,
              "target evidence writer request ABI changed");
static_assert(sizeof(knhv::TargetEvidenceManifestWriteResult) == 280,
              "target evidence writer result ABI changed");
#endif
