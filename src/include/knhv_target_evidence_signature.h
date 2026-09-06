#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kTargetEvidenceSignatureContractVersion = 1U;
constexpr u32 kTargetEvidenceSignatureMaxPath = 32768U;
constexpr u32 kTargetEvidenceSignatureMaxStructSize = 4096U;

constexpr u32 kTargetEvidenceSignatureFlagAllowPrivateTestRoot = 1U << 0;
constexpr u32 kTargetEvidenceSignatureKnownFlagMask =
    kTargetEvidenceSignatureFlagAllowPrivateTestRoot;

enum class TargetEvidenceSignatureStatus : u32 {
    Trusted = 0,
    InvalidArgument = 1,
    FileNotFound = 2,
    NotSigned = 3,
    Untrusted = 4,
    PrivateTestRoot = 5,
    VerificationUnavailable = 6,
};

constexpr u32 kTargetEvidenceSignatureResultPrivateRootAccepted = 1U << 0;

#pragma pack(push, 8)

struct TargetEvidenceSignatureRequest {
    u32 size;
    u32 version;
    u32 flags;
    u32 reserved;
};

struct TargetEvidenceSignatureResult {
    u32 size;
    u32 version;
    u32 status;
    u32 wintrust_status;
    u32 result_flags;
    u32 reserved;
};

#pragma pack(pop)

bool IsTargetEvidenceSignatureRequestValid(
    const TargetEvidenceSignatureRequest* request);
bool IsTargetEvidenceSignatureResultValid(
    const TargetEvidenceSignatureResult* result);
TargetEvidenceSignatureStatus VerifyTargetEvidenceFileSignature(
    const wchar_t* path, const TargetEvidenceSignatureRequest* request,
    TargetEvidenceSignatureResult* result);
const char* TargetEvidenceSignatureStatusText(
    TargetEvidenceSignatureStatus status);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceSignatureRequest) == 16,
              "target evidence signature request ABI changed");
static_assert(sizeof(knhv::TargetEvidenceSignatureResult) == 24,
              "target evidence signature result ABI changed");
#endif
