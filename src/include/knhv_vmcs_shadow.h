#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kVmcsShadowContractVersion = 1U;
constexpr u32 kVmcsShadowMaxStructSize = 4096U;
constexpr u32 kVmcsShadowMaxFields = 128U;
constexpr u32 kVmcsShadowBitmapBytes = kVmcsShadowMaxFields / 8U;
constexpr u32 kVmcsShadowPageSize = 4096U;
constexpr u32 kVmcsShadowMaxPhysicalAddressBits = 52U;
constexpr u64 kVmcsShadowNoLinkPointer = ~0ULL;

constexpr u64 kVmcsShadowCapSupported = 1ULL << 0;
constexpr u64 kVmcsShadowCapLinkPointer = 1ULL << 1;
constexpr u64 kVmcsShadowCapReadBitmap = 1ULL << 2;
constexpr u64 kVmcsShadowCapWriteBitmap = 1ULL << 3;
constexpr u64 kVmcsShadowKnownCapabilityMask =
    kVmcsShadowCapSupported | kVmcsShadowCapLinkPointer |
    kVmcsShadowCapReadBitmap | kVmcsShadowCapWriteBitmap;

constexpr u32 kVmcsShadowEnableLinkPointer = 1U << 0;
constexpr u32 kVmcsShadowEnableReadBitmap = 1U << 1;
constexpr u32 kVmcsShadowEnableWriteBitmap = 1U << 2;
constexpr u32 kVmcsShadowKnownConfigFlagMask =
    kVmcsShadowEnableLinkPointer | kVmcsShadowEnableReadBitmap |
    kVmcsShadowEnableWriteBitmap;

enum class VmcsShadowState : u32 {
    Empty = 0,
    Active = 1,
    Cleared = 2,
    Quarantined = 3,
};

enum class VmcsShadowAccessOperation : u32 {
    Read = 1,
    Write = 2,
};

enum class VmcsShadowAccessResult : u32 {
    Shadow = 0,
    ReflectExit = 1,
    Invalid = 2,
    Stale = 3,
    Quarantined = 4,
};

#pragma pack(push, 8)

struct VmcsShadowCapabilities {
    u32 size;
    u32 version;
    u64 feature_flags;
    u32 max_fields;
    u32 physical_address_bits;
    u64 generation;
    u64 reserved;
};

struct VmcsShadowConfig {
    u32 size;
    u32 version;
    u64 link_pointer;
    u64 read_bitmap_physical;
    u64 write_bitmap_physical;
    u32 flags;
    u32 reserved;
    u64 generation;
    u8 read_bitmap[kVmcsShadowBitmapBytes];
    u8 write_bitmap[kVmcsShadowBitmapBytes];
};

struct VmcsShadowImage {
    u32 size;
    u32 version;
    u64 generation;
    u32 state;
    u32 field_count;
    u64 fields[kVmcsShadowMaxFields];
    u64 dirty_bitmap[2];
    u64 reserved[2];
};

struct VmcsShadowAccess {
    u32 size;
    u32 version;
    u32 field_index;
    u32 encoding;
    u32 operation;
    u32 reserved;
    u64 value;
    u64 generation;
};

struct VmcsShadowDecision {
    u32 size;
    u32 version;
    u32 result;
    u32 field_index;
    u32 reserved;
    u64 value;
    u64 generation;
};

#pragma pack(pop)

bool IsVmcsShadowCapabilitiesValid(
    const VmcsShadowCapabilities* capabilities);
bool IsVmcsShadowConfigValid(const VmcsShadowConfig* config,
                             u32 max_physical_address_bits,
                             u32 max_fields);
bool IsVmcsShadowImageValid(const VmcsShadowImage* image);
bool IsVmcsShadowAccessValid(const VmcsShadowAccess* access);

bool BeginVmcsShadow(const VmcsShadowCapabilities* capabilities,
                     const VmcsShadowConfig* config,
                     VmcsShadowImage* image);
bool ClearVmcsShadow(VmcsShadowImage* image, u64 generation);
bool RebindVmcsShadow(const VmcsShadowCapabilities* capabilities,
                      const VmcsShadowConfig* config,
                      u64 expected_generation, VmcsShadowImage* image);
bool QuarantineVmcsShadow(VmcsShadowImage* image, u64 generation);

VmcsShadowAccessResult ClassifyVmcsShadowAccess(
    const VmcsShadowCapabilities* capabilities,
    const VmcsShadowConfig* config, const VmcsShadowImage* image,
    const VmcsShadowAccess* access, u64 generation,
    VmcsShadowDecision* decision);
VmcsShadowAccessResult ApplyVmcsShadowAccess(
    const VmcsShadowCapabilities* capabilities,
    const VmcsShadowConfig* config, VmcsShadowImage* image,
    const VmcsShadowAccess* access, u64 generation,
    VmcsShadowDecision* decision);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::VmcsShadowCapabilities) == 40,
              "VMCS shadow capabilities ABI changed");
static_assert(sizeof(knhv::VmcsShadowConfig) == 80,
              "VMCS shadow config ABI changed");
static_assert(sizeof(knhv::VmcsShadowImage) == 1080,
              "VMCS shadow image ABI changed");
static_assert(sizeof(knhv::VmcsShadowAccess) == 40,
              "VMCS shadow access ABI changed");
static_assert(sizeof(knhv::VmcsShadowDecision) == 40,
              "VMCS shadow decision ABI changed");
#endif
