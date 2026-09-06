#pragma once

#include "knhv_target_snapshot.h"

namespace knhv {

// this codec stores an approved snapshot and its raw sample evidence
constexpr u32 kTargetEvidenceSnapshotWireVersion = 1U;
constexpr u32 kTargetEvidenceSnapshotWireDigestSize = 32U;
constexpr u32 kTargetEvidenceSnapshotWireMaxSize = 2U * 1024U * 1024U;

enum class TargetEvidenceSnapshotCodecStatus : u32 {
    Success = 0,
    InvalidArgument = 1,
    BufferTooSmall = 2,
    InvalidHeader = 3,
    UnsupportedVersion = 4,
    InvalidLength = 5,
    SnapshotInvalid = 6,
    DigestUnavailable = 7,
    DigestMismatch = 8,
};

#pragma pack(push, 1)
struct TargetEvidenceSnapshotWireHeader {
    u8 magic[8];
    u32 version;
    u32 header_size;
    u32 snapshot_size;
    u32 cpu_sample_size;
    u32 vmx_sample_size;
    u32 cpu_sample_count;
    u32 vmx_sample_count;
    u32 payload_size;
    u32 digest_size;
    u32 envelope_size;
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 reserved3;
};
#pragma pack(pop)

constexpr u32 kTargetEvidenceSnapshotWireHeaderSize =
    sizeof(TargetEvidenceSnapshotWireHeader);
constexpr u32 kTargetEvidenceSnapshotWirePayloadFixedSize =
    sizeof(TargetEvidenceSnapshot);

u32 GetTargetEvidenceSnapshotWireSize(u32 cpu_sample_count,
                                      u32 vmx_sample_count);
TargetEvidenceSnapshotCodecStatus InspectTargetEvidenceSnapshotPackage(
    const u8* input, u32 input_size,
    TargetEvidenceSnapshotWireHeader* header);
TargetEvidenceSnapshotCodecStatus GetTargetEvidenceSnapshotPackageDigest(
    const u8* input, u32 input_size, u8* digest);
TargetEvidenceSnapshotCodecStatus EncodeTargetEvidenceSnapshotPackage(
    const TargetEvidenceSnapshot* snapshot,
    const CpuMatrixSample* cpu_samples, u32 cpu_sample_count,
    const VmxCapabilitySample* vmx_samples, u32 vmx_sample_count, u8* output,
    u32 capacity, u32* written);
TargetEvidenceSnapshotCodecStatus DecodeTargetEvidenceSnapshotPackage(
    const u8* input, u32 input_size, TargetEvidenceSnapshot* snapshot,
    CpuMatrixSample* cpu_samples, u32 cpu_capacity, u32* cpu_sample_count,
    VmxCapabilitySample* vmx_samples, u32 vmx_capacity,
    u32* vmx_sample_count);
const char* TargetEvidenceSnapshotCodecStatusText(
    TargetEvidenceSnapshotCodecStatus status);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TargetEvidenceSnapshotWireHeader) == 64,
              "target evidence snapshot wire header ABI changed");
#endif
