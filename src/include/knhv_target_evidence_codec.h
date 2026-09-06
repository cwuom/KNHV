#pragma once

#include "knhv_target_evidence.h"

namespace knhv {

// this codec is host-only and is not linked into a kernel image
constexpr u32 kTargetEvidenceWireVersion = 1U;
constexpr u32 kTargetEvidenceWireDigestSize = 32U;
constexpr u32 kTargetEvidenceWireMaxSize = 4096U;
constexpr u32 kTargetEvidenceMaxSignatureSize = 16384U;

enum class TargetEvidenceCodecStatus : u32 {
    Success = 0,
    InvalidArgument = 1,
    BufferTooSmall = 2,
    InvalidHeader = 3,
    UnsupportedVersion = 4,
    InvalidLength = 5,
    InvalidManifest = 6,
    DigestUnavailable = 7,
    DigestMismatch = 8,
    SignatureUnavailable = 9,
    SignatureInvalid = 10,
};

#pragma pack(push, 1)
struct TargetEvidenceWireHeader {
    u8 magic[8];
    u32 version;
    u32 header_size;
    u32 payload_size;
    u32 digest_size;
    u32 envelope_size;
    u32 reserved;
};
#pragma pack(pop)

constexpr u32 kTargetEvidenceWireHeaderSize =
    sizeof(TargetEvidenceWireHeader);
constexpr u32 kTargetEvidenceWirePayloadSize = sizeof(TargetEvidenceManifest);
constexpr u32 kTargetEvidenceWireEnvelopeSize =
    kTargetEvidenceWireHeaderSize + kTargetEvidenceWirePayloadSize +
    kTargetEvidenceWireDigestSize;

using TargetEvidenceSignatureVerifier = bool (*) (
    const u8* content, u32 content_size, const u8* signature,
    u32 signature_size, void* context);

TargetEvidenceCodecStatus EncodeTargetEvidencePackage(
    const TargetEvidenceManifest* manifest, u8* output, u32 capacity,
    u32* written);
TargetEvidenceCodecStatus DecodeTargetEvidencePackage(
    const u8* input, u32 input_size, TargetEvidenceManifest* manifest);
TargetEvidenceCodecStatus VerifyTargetEvidenceDetachedSignature(
    const u8* content, u32 content_size, const u8* signature,
    u32 signature_size, TargetEvidenceSignatureVerifier verifier,
    void* context);
const char* TargetEvidenceCodecStatusText(TargetEvidenceCodecStatus status);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceWireHeader) == 32,
              "target evidence wire header ABI changed");
static_assert(knhv::kTargetEvidenceWireEnvelopeSize == 320,
              "target evidence wire envelope size changed");
#endif
