#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstring>
#include <vector>

#include "knhv_target_evidence_codec.h"

namespace knhv {
namespace {

constexpr u8 kWireMagic[8] = {'K', 'N', 'H', 'V', 'E', 'V', '0', '1'};

bool IsDigestEqual(const u8* left, const u8* right, u32 size) {
    if (left == nullptr || right == nullptr) return false;
    u8 difference = 0U;
    for (u32 index = 0U; index < size; ++index) {
        difference = static_cast<u8>(difference | (left[index] ^ right[index]));
    }
    return difference == 0U;
}

bool ComputeSha256(const u8* input, u32 size, u8 digest[32]) {
    if (input == nullptr || digest == nullptr || size == 0U) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ULONG object_size = 0U;
    ULONG result_size = 0U;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
        &result_size, 0U);
    if (!BCRYPT_SUCCESS(status) || result_size != sizeof(object_size) ||
        object_size == 0U || object_size > (1U << 20U)) {
        BCryptCloseAlgorithmProvider(algorithm, 0U);
        return false;
    }

    std::vector<UCHAR> object(object_size);
    status = BCryptCreateHash(algorithm, &hash, object.data(), object_size,
                              nullptr, 0U, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(algorithm, 0U);
        return false;
    }

    status = BCryptHashData(hash, const_cast<PUCHAR>(input), size, 0U);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, digest, kTargetEvidenceWireDigestSize,
                                  0U);
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0U);
    return BCRYPT_SUCCESS(status);
}

void InitializeHeader(TargetEvidenceWireHeader* header) {
    *header = {};
    std::memcpy(header->magic, kWireMagic, sizeof(kWireMagic));
    header->version = kTargetEvidenceWireVersion;
    header->header_size = kTargetEvidenceWireHeaderSize;
    header->payload_size = kTargetEvidenceWirePayloadSize;
    header->digest_size = kTargetEvidenceWireDigestSize;
    header->envelope_size = kTargetEvidenceWireEnvelopeSize;
}

bool IsMagicValid(const TargetEvidenceWireHeader& header) {
    return std::memcmp(header.magic, kWireMagic, sizeof(kWireMagic)) == 0;
}

TargetEvidenceCodecStatus ValidateHeader(
    const TargetEvidenceWireHeader& header, u32 input_size) {
    if (!IsMagicValid(header)) return TargetEvidenceCodecStatus::InvalidHeader;
    if (header.version != kTargetEvidenceWireVersion) {
        return TargetEvidenceCodecStatus::UnsupportedVersion;
    }
    if (header.header_size != kTargetEvidenceWireHeaderSize ||
        header.payload_size != kTargetEvidenceWirePayloadSize ||
        header.digest_size != kTargetEvidenceWireDigestSize ||
        header.envelope_size != kTargetEvidenceWireEnvelopeSize ||
        header.reserved != 0U) {
        return TargetEvidenceCodecStatus::InvalidHeader;
    }
    if (header.envelope_size > kTargetEvidenceWireMaxSize ||
        input_size != header.envelope_size) {
        return TargetEvidenceCodecStatus::InvalidLength;
    }
    return TargetEvidenceCodecStatus::Success;
}

}  // namespace

TargetEvidenceCodecStatus EncodeTargetEvidencePackage(
    const TargetEvidenceManifest* manifest, u8* output, u32 capacity,
    u32* written) {
    if (written == nullptr) return TargetEvidenceCodecStatus::InvalidArgument;
    *written = 0U;
    if (manifest == nullptr || output == nullptr) {
        return TargetEvidenceCodecStatus::InvalidArgument;
    }
    if (capacity < kTargetEvidenceWireEnvelopeSize) {
        return TargetEvidenceCodecStatus::BufferTooSmall;
    }
    const TargetEvidenceManifest snapshot = *manifest;
    if (!IsTargetEvidenceManifestValid(&snapshot)) {
        return TargetEvidenceCodecStatus::InvalidManifest;
    }

    TargetEvidenceWireHeader header{};
    InitializeHeader(&header);
    std::memcpy(output, &header, sizeof(header));
    std::memcpy(output + kTargetEvidenceWireHeaderSize, &snapshot,
                sizeof(snapshot));
    u8 digest[kTargetEvidenceWireDigestSize] = {};
    if (!ComputeSha256(output,
                       kTargetEvidenceWireHeaderSize +
                           kTargetEvidenceWirePayloadSize,
                       digest)) {
        std::memset(output, 0, kTargetEvidenceWireEnvelopeSize);
        return TargetEvidenceCodecStatus::DigestUnavailable;
    }
    std::memcpy(output + kTargetEvidenceWireHeaderSize +
                    kTargetEvidenceWirePayloadSize,
                digest, sizeof(digest));
    *written = kTargetEvidenceWireEnvelopeSize;
    return TargetEvidenceCodecStatus::Success;
}

TargetEvidenceCodecStatus DecodeTargetEvidencePackage(
    const u8* input, u32 input_size, TargetEvidenceManifest* manifest) {
    if (input == nullptr || manifest == nullptr) {
        return TargetEvidenceCodecStatus::InvalidArgument;
    }
    *manifest = {};
    if (input_size < kTargetEvidenceWireHeaderSize ||
        input_size > kTargetEvidenceWireMaxSize) {
        return TargetEvidenceCodecStatus::InvalidLength;
    }

    TargetEvidenceWireHeader header{};
    std::memcpy(&header, input, sizeof(header));
    const TargetEvidenceCodecStatus header_status =
        ValidateHeader(header, input_size);
    if (header_status != TargetEvidenceCodecStatus::Success) {
        return header_status;
    }

    u8 expected_digest[kTargetEvidenceWireDigestSize] = {};
    if (!ComputeSha256(input,
                       kTargetEvidenceWireHeaderSize +
                           kTargetEvidenceWirePayloadSize,
                       expected_digest)) {
        return TargetEvidenceCodecStatus::DigestUnavailable;
    }
    const u8* actual_digest =
        input + kTargetEvidenceWireHeaderSize + kTargetEvidenceWirePayloadSize;
    if (!IsDigestEqual(expected_digest, actual_digest,
                       kTargetEvidenceWireDigestSize)) {
        return TargetEvidenceCodecStatus::DigestMismatch;
    }

    TargetEvidenceManifest decoded{};
    std::memcpy(&decoded, input + kTargetEvidenceWireHeaderSize,
                sizeof(decoded));
    if (!IsTargetEvidenceManifestValid(&decoded)) {
        *manifest = {};
        return TargetEvidenceCodecStatus::InvalidManifest;
    }
    *manifest = decoded;
    return TargetEvidenceCodecStatus::Success;
}

TargetEvidenceCodecStatus VerifyTargetEvidenceDetachedSignature(
    const u8* content, u32 content_size, const u8* signature,
    u32 signature_size, TargetEvidenceSignatureVerifier verifier,
    void* context) {
    if (content == nullptr || content_size == 0U ||
        content_size > kTargetEvidenceWireMaxSize || signature == nullptr ||
        signature_size == 0U || signature_size > kTargetEvidenceMaxSignatureSize) {
        return TargetEvidenceCodecStatus::InvalidArgument;
    }
    if (verifier == nullptr) {
        return TargetEvidenceCodecStatus::SignatureUnavailable;
    }
    return verifier(content, content_size, signature, signature_size, context)
               ? TargetEvidenceCodecStatus::Success
               : TargetEvidenceCodecStatus::SignatureInvalid;
}

const char* TargetEvidenceCodecStatusText(TargetEvidenceCodecStatus status) {
    switch (status) {
        case TargetEvidenceCodecStatus::Success:
            return "success";
        case TargetEvidenceCodecStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceCodecStatus::BufferTooSmall:
            return "buffer-too-small";
        case TargetEvidenceCodecStatus::InvalidHeader:
            return "invalid-header";
        case TargetEvidenceCodecStatus::UnsupportedVersion:
            return "unsupported-version";
        case TargetEvidenceCodecStatus::InvalidLength:
            return "invalid-length";
        case TargetEvidenceCodecStatus::InvalidManifest:
            return "invalid-manifest";
        case TargetEvidenceCodecStatus::DigestUnavailable:
            return "digest-unavailable";
        case TargetEvidenceCodecStatus::DigestMismatch:
            return "digest-mismatch";
        case TargetEvidenceCodecStatus::SignatureUnavailable:
            return "signature-unavailable";
        case TargetEvidenceCodecStatus::SignatureInvalid:
            return "signature-invalid";
        default:
            return "unknown";
    }
}

}  // namespace knhv
