#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <new>

#include "knhv_target_snapshot_codec.h"

namespace knhv {
namespace {

constexpr u8 kWireMagic[8] = {'K', 'N', 'H', 'V', 'S', 'N', 'P', '1'};

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

    UCHAR* object = new (std::nothrow) UCHAR[object_size];
    if (object == nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0U);
        return false;
    }
    status = BCryptCreateHash(algorithm, &hash, object, object_size, nullptr,
                              0U, 0U);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptHashData(hash, const_cast<PUCHAR>(input), size, 0U);
    }
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(hash, digest,
                                  kTargetEvidenceSnapshotWireDigestSize, 0U);
    }

    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0U);
    delete[] object;
    return BCRYPT_SUCCESS(status);
}

bool IsMagicValid(const TargetEvidenceSnapshotWireHeader& header) {
    return std::memcmp(header.magic, kWireMagic, sizeof(kWireMagic)) == 0;
}

u32 CalculatePayloadSize(u32 cpu_sample_count, u32 vmx_sample_count) {
    const std::uint64_t payload =
        static_cast<std::uint64_t>(sizeof(TargetEvidenceSnapshot)) +
        static_cast<std::uint64_t>(cpu_sample_count) *
            sizeof(CpuMatrixSample) +
        static_cast<std::uint64_t>(vmx_sample_count) *
            sizeof(VmxCapabilitySample);
    if (payload > static_cast<std::uint64_t>(
                      kTargetEvidenceSnapshotWireMaxSize) ||
        payload > 0xFFFFFFFFULL) {
        return 0U;
    }
    return static_cast<u32>(payload);
}

u32 CalculateEnvelopeSize(u32 payload_size) {
    const std::uint64_t envelope =
        static_cast<std::uint64_t>(kTargetEvidenceSnapshotWireHeaderSize) +
        payload_size + kTargetEvidenceSnapshotWireDigestSize;
    if (envelope > kTargetEvidenceSnapshotWireMaxSize ||
        envelope > 0xFFFFFFFFULL) {
        return 0U;
    }
    return static_cast<u32>(envelope);
}

void InitializeHeader(TargetEvidenceSnapshotWireHeader* header,
                      u32 cpu_sample_count, u32 vmx_sample_count) {
    *header = {};
    std::memcpy(header->magic, kWireMagic, sizeof(kWireMagic));
    header->version = kTargetEvidenceSnapshotWireVersion;
    header->header_size = kTargetEvidenceSnapshotWireHeaderSize;
    header->snapshot_size = sizeof(TargetEvidenceSnapshot);
    header->cpu_sample_size = sizeof(CpuMatrixSample);
    header->vmx_sample_size = sizeof(VmxCapabilitySample);
    header->cpu_sample_count = cpu_sample_count;
    header->vmx_sample_count = vmx_sample_count;
    header->payload_size = CalculatePayloadSize(cpu_sample_count,
                                                vmx_sample_count);
    header->digest_size = kTargetEvidenceSnapshotWireDigestSize;
    header->envelope_size = CalculateEnvelopeSize(header->payload_size);
}

TargetEvidenceSnapshotCodecStatus ValidateHeader(
    const TargetEvidenceSnapshotWireHeader& header, u32 input_size) {
    if (!IsMagicValid(header)) {
        return TargetEvidenceSnapshotCodecStatus::InvalidHeader;
    }
    if (header.version != kTargetEvidenceSnapshotWireVersion) {
        return TargetEvidenceSnapshotCodecStatus::UnsupportedVersion;
    }
    if (header.header_size != kTargetEvidenceSnapshotWireHeaderSize ||
        header.snapshot_size != sizeof(TargetEvidenceSnapshot) ||
        header.cpu_sample_size != sizeof(CpuMatrixSample) ||
        header.vmx_sample_size != sizeof(VmxCapabilitySample) ||
        header.digest_size != kTargetEvidenceSnapshotWireDigestSize ||
        header.reserved0 != 0U || header.reserved1 != 0U ||
        header.reserved2 != 0U || header.reserved3 != 0U) {
        return TargetEvidenceSnapshotCodecStatus::InvalidHeader;
    }
    if (header.cpu_sample_count > kCpuMatrixMaxProcessors ||
        header.vmx_sample_count > kVmxCapabilityMaxProcessors) {
        return TargetEvidenceSnapshotCodecStatus::InvalidLength;
    }
    const u32 expected_payload =
        CalculatePayloadSize(header.cpu_sample_count,
                             header.vmx_sample_count);
    const u32 expected_envelope = CalculateEnvelopeSize(expected_payload);
    if (expected_payload == 0U || expected_envelope == 0U ||
        header.payload_size != expected_payload ||
        header.envelope_size != expected_envelope ||
        header.envelope_size > kTargetEvidenceSnapshotWireMaxSize ||
        input_size != header.envelope_size) {
        return TargetEvidenceSnapshotCodecStatus::InvalidLength;
    }
    return TargetEvidenceSnapshotCodecStatus::Success;
}

void ClearDecodeOutputs(TargetEvidenceSnapshot* snapshot,
                        CpuMatrixSample* cpu_samples, u32* cpu_sample_count,
                        VmxCapabilitySample* vmx_samples,
                        u32* vmx_sample_count) {
    if (snapshot != nullptr) *snapshot = {};
    if (cpu_sample_count != nullptr) *cpu_sample_count = 0U;
    if (vmx_sample_count != nullptr) *vmx_sample_count = 0U;
    (void)cpu_samples;
    (void)vmx_samples;
}

}  // namespace

u32 GetTargetEvidenceSnapshotWireSize(u32 cpu_sample_count,
                                      u32 vmx_sample_count) {
    if (cpu_sample_count > kCpuMatrixMaxProcessors ||
        vmx_sample_count > kVmxCapabilityMaxProcessors) {
        return 0U;
    }
    const u32 payload = CalculatePayloadSize(cpu_sample_count,
                                             vmx_sample_count);
    return payload == 0U ? 0U : CalculateEnvelopeSize(payload);
}

TargetEvidenceSnapshotCodecStatus InspectTargetEvidenceSnapshotPackage(
    const u8* input, u32 input_size,
    TargetEvidenceSnapshotWireHeader* header) {
    if (header != nullptr) *header = {};
    if (input == nullptr || header == nullptr) {
        return TargetEvidenceSnapshotCodecStatus::InvalidArgument;
    }
    if (input_size < kTargetEvidenceSnapshotWireHeaderSize ||
        input_size > kTargetEvidenceSnapshotWireMaxSize) {
        return TargetEvidenceSnapshotCodecStatus::InvalidLength;
    }
    std::memcpy(header, input, sizeof(*header));
    return ValidateHeader(*header, input_size);
}

TargetEvidenceSnapshotCodecStatus EncodeTargetEvidenceSnapshotPackage(
    const TargetEvidenceSnapshot* snapshot, const CpuMatrixSample* cpu_samples,
    u32 cpu_sample_count, const VmxCapabilitySample* vmx_samples,
    u32 vmx_sample_count, u8* output, u32 capacity, u32* written) {
    if (written == nullptr) return TargetEvidenceSnapshotCodecStatus::
        InvalidArgument;
    *written = 0U;
    if (snapshot == nullptr || output == nullptr ||
        (cpu_sample_count != 0U && cpu_samples == nullptr) ||
        (vmx_sample_count != 0U && vmx_samples == nullptr)) {
        return TargetEvidenceSnapshotCodecStatus::InvalidArgument;
    }
    const u32 envelope_size =
        GetTargetEvidenceSnapshotWireSize(cpu_sample_count, vmx_sample_count);
    if (envelope_size == 0U) {
        return TargetEvidenceSnapshotCodecStatus::InvalidLength;
    }
    if (capacity < envelope_size) {
        return TargetEvidenceSnapshotCodecStatus::BufferTooSmall;
    }
    if (!IsTargetEvidenceSnapshotValid(snapshot, cpu_samples,
                                       cpu_sample_count, vmx_samples,
                                       vmx_sample_count)) {
        return TargetEvidenceSnapshotCodecStatus::SnapshotInvalid;
    }

    TargetEvidenceSnapshotWireHeader header{};
    InitializeHeader(&header, cpu_sample_count, vmx_sample_count);
    std::memcpy(output, &header, sizeof(header));
    u8* payload = output + kTargetEvidenceSnapshotWireHeaderSize;
    std::memcpy(payload, snapshot, sizeof(*snapshot));
    payload += sizeof(*snapshot);
    if (cpu_sample_count != 0U) {
        const std::size_t byte_count =
            static_cast<std::size_t>(cpu_sample_count) *
            sizeof(CpuMatrixSample);
        std::memcpy(payload, cpu_samples, byte_count);
        payload += byte_count;
    }
    if (vmx_sample_count != 0U) {
        const std::size_t byte_count =
            static_cast<std::size_t>(vmx_sample_count) *
            sizeof(VmxCapabilitySample);
        std::memcpy(payload, vmx_samples, byte_count);
    }
    u8 digest[kTargetEvidenceSnapshotWireDigestSize] = {};
    if (!ComputeSha256(output, header.header_size + header.payload_size,
                       digest)) {
        std::memset(output, 0, envelope_size);
        return TargetEvidenceSnapshotCodecStatus::DigestUnavailable;
    }
    std::memcpy(output + header.header_size + header.payload_size, digest,
                sizeof(digest));
    *written = envelope_size;
    return TargetEvidenceSnapshotCodecStatus::Success;
}

TargetEvidenceSnapshotCodecStatus DecodeTargetEvidenceSnapshotPackage(
    const u8* input, u32 input_size, TargetEvidenceSnapshot* snapshot,
    CpuMatrixSample* cpu_samples, u32 cpu_capacity, u32* cpu_sample_count,
    VmxCapabilitySample* vmx_samples, u32 vmx_capacity,
    u32* vmx_sample_count) {
    ClearDecodeOutputs(snapshot, cpu_samples, cpu_sample_count, vmx_samples,
                      vmx_sample_count);
    if (snapshot == nullptr || cpu_sample_count == nullptr ||
        vmx_sample_count == nullptr) {
        return TargetEvidenceSnapshotCodecStatus::InvalidArgument;
    }
    TargetEvidenceSnapshotWireHeader header{};
    const TargetEvidenceSnapshotCodecStatus inspect_status =
        InspectTargetEvidenceSnapshotPackage(input, input_size, &header);
    if (inspect_status != TargetEvidenceSnapshotCodecStatus::Success) {
        return inspect_status;
    }
    if (header.cpu_sample_count > cpu_capacity ||
        header.vmx_sample_count > vmx_capacity ||
        (header.cpu_sample_count != 0U && cpu_samples == nullptr) ||
        (header.vmx_sample_count != 0U && vmx_samples == nullptr)) {
        return TargetEvidenceSnapshotCodecStatus::BufferTooSmall;
    }

    u8 expected_digest[kTargetEvidenceSnapshotWireDigestSize] = {};
    if (!ComputeSha256(input, header.header_size + header.payload_size,
                       expected_digest)) {
        return TargetEvidenceSnapshotCodecStatus::DigestUnavailable;
    }
    const u8* actual_digest =
        input + header.header_size + header.payload_size;
    if (!IsDigestEqual(expected_digest, actual_digest,
                       kTargetEvidenceSnapshotWireDigestSize)) {
        return TargetEvidenceSnapshotCodecStatus::DigestMismatch;
    }

    const u8* payload = input + header.header_size;
    TargetEvidenceSnapshot decoded{};
    std::memcpy(&decoded, payload, sizeof(decoded));
    payload += sizeof(decoded);
    if (header.cpu_sample_count != 0U) {
        const std::size_t byte_count =
            static_cast<std::size_t>(header.cpu_sample_count) *
            sizeof(CpuMatrixSample);
        std::memcpy(cpu_samples, payload, byte_count);
        payload += byte_count;
    }
    if (header.vmx_sample_count != 0U) {
        const std::size_t byte_count =
            static_cast<std::size_t>(header.vmx_sample_count) *
            sizeof(VmxCapabilitySample);
        std::memcpy(vmx_samples, payload, byte_count);
    }
    if (!IsTargetEvidenceSnapshotValid(
            &decoded, cpu_samples, header.cpu_sample_count, vmx_samples,
            header.vmx_sample_count)) {
        *snapshot = {};
        if (header.cpu_sample_count != 0U) {
            std::memset(cpu_samples, 0,
                        static_cast<std::size_t>(header.cpu_sample_count) *
                            sizeof(CpuMatrixSample));
        }
        if (header.vmx_sample_count != 0U) {
            std::memset(vmx_samples, 0,
                        static_cast<std::size_t>(header.vmx_sample_count) *
                            sizeof(VmxCapabilitySample));
        }
        return TargetEvidenceSnapshotCodecStatus::SnapshotInvalid;
    }
    *snapshot = decoded;
    *cpu_sample_count = header.cpu_sample_count;
    *vmx_sample_count = header.vmx_sample_count;
    return TargetEvidenceSnapshotCodecStatus::Success;
}

const char* TargetEvidenceSnapshotCodecStatusText(
    TargetEvidenceSnapshotCodecStatus status) {
    switch (status) {
        case TargetEvidenceSnapshotCodecStatus::Success:
            return "success";
        case TargetEvidenceSnapshotCodecStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceSnapshotCodecStatus::BufferTooSmall:
            return "buffer-too-small";
        case TargetEvidenceSnapshotCodecStatus::InvalidHeader:
            return "invalid-header";
        case TargetEvidenceSnapshotCodecStatus::UnsupportedVersion:
            return "unsupported-version";
        case TargetEvidenceSnapshotCodecStatus::InvalidLength:
            return "invalid-length";
        case TargetEvidenceSnapshotCodecStatus::SnapshotInvalid:
            return "snapshot-invalid";
        case TargetEvidenceSnapshotCodecStatus::DigestUnavailable:
            return "digest-unavailable";
        case TargetEvidenceSnapshotCodecStatus::DigestMismatch:
            return "digest-mismatch";
        default:
            return "unknown";
    }
}

}  // namespace knhv
