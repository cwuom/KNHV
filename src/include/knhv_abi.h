#pragma once

// the public contract uses fixed-width fields and explicit sizes so a client
// can negotiate additions without depending on compiler padding

namespace knhv {

using u8 = unsigned __int8;
using u16 = unsigned __int16;
using u32 = unsigned __int32;
using u64 = unsigned __int64;

constexpr u32 kAbiVersion = 1U;
constexpr u32 kAbiMinVersion = 1U;

enum class HvStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    UnsupportedMode = 2,
    CapabilityMismatch = 3,
    HardwareOwnerConflict = 4,
    NestedUnavailable = 5,
    VmfailInvalid = 6,
    VmfailValid = 7,
    Cancelled = 8,
    Timeout = 9,
    Quarantined = 10,
    LoadOnly = 11,
    IncompatibleProvider = 12,
    VirtualUnsupported = 13,
    ArchUnsupported = 14,
    BootHandoffFailed = 15,
    RecoveryRequired = 16,
    HardwareUnsupported = 17,
    BufferTooSmall = 18,
    Busy = 19,
};

enum class HvProviderKind : u32 {
    None = 0,
    BootL0Interposer = 1,
    CooperativeL1 = 2,
    KnownLegacyAdapter = 3,
    LoadOnly = 4,
    ExternalL0Fallback = 5,
    WhpClient = 6,
    NativeExclusiveBaseline = 7,
};

enum class HvMode : u32 {
    BootL0Interposer = 1,
    CooperativeL1 = 2,
    KnownLegacyCompat = 3,
    LoadOnly = 4,
    ExternalL0Fallback = 5,
    NativeExclusiveBaseline = 6,
    WhpClient = 7,
};

constexpr u64 kCapVmx = 1ULL << 0;
constexpr u64 kCapEpt = 1ULL << 1;
constexpr u64 kCapVpid = 1ULL << 2;
constexpr u64 kCapNestedVmx = 1ULL << 3;
constexpr u64 kCapEnlightenedVmcs = 1ULL << 4;
constexpr u64 kCapVirtualTlbFlush = 1ULL << 5;
constexpr u64 kCapWhpPartition = 1ULL << 6;
constexpr u64 kCapBootL0 = 1ULL << 7;
constexpr u64 kCapIommu = 1ULL << 8;
constexpr u64 kCapVirtualApic = 1ULL << 9;
constexpr u64 kCapTscContract = 1ULL << 10;
constexpr u64 kKnownCapabilityMask = (1ULL << 11) - 1ULL;

constexpr u32 kFlagOuterL0Active = 1U << 0;
constexpr u32 kFlagNativeVmxReady = 1U << 1;
constexpr u32 kFlagBootHandoffVerified = 1U << 2;
constexpr u32 kFlagKnhvBootL0Active = 1U << 3;
constexpr u32 kFlagNestedVmx = 1U << 4;
constexpr u32 kFlagWhpPartition = 1U << 5;
constexpr u32 kFlagSyntheticSnapshot = 1U << 6;

#pragma pack(push, 8)

struct HvCapabilitySnapshot {
    u32 version;
    u32 size;
    u64 feature_bits;
    u32 max_physical_address_bits;
    u32 e_vmcs_version;
    u32 whp_api_version;
    u32 hypervisor_vendor_length;
    u32 status_flags;
    u32 boot_generation;
    u32 owner_generation;
    u64 feature_hash;
};

struct HvProviderRegistration {
    u32 version;
    u32 size;
    u8 provider_guid[16];
    u32 min_abi_version;
    u32 max_abi_version;
    HvProviderKind kind;
    u32 security_policy_version;
    u64 advertised_features;
    u32 max_vcpus;
    u32 max_guest_pages;
    u64 policy_hash;
    u64 reserved[2];
};

struct HvProviderRequest {
    u32 version;
    u32 size;
    HvMode mode;
    u32 identity_verified;
    u32 legacy_manifest_match;
    u32 reserved;
    u64 requested_features;
};

struct HvQueryCapsIn {
    u32 version;
    u32 size;
    u64 request_id;
};

struct HvSessionKey {
    u64 client_id;
    u32 generation;
    u32 reserved;
};

struct HvQuerySessionIn {
    u32 version;
    u32 size;
    u64 request_id;
    HvSessionKey session;
};

struct HvQueryCapsOut {
    u32 version;
    u32 size;
    u64 request_id;
    HvStatus status;
    HvCapabilitySnapshot snapshot;
};

struct HvRegisterClientIn {
    u32 version;
    u32 size;
    u64 request_id;
    HvProviderRegistration registration;
};

struct HvRegisterClientOut {
    u32 version;
    u32 size;
    u64 request_id;
    HvStatus status;
    HvProviderKind provider;
    u32 load_success;
    u32 registration_ready;
    u32 virtualization_ready;
    u64 client_id;
    u32 generation;
    u32 reserved;
};

struct HvSessionStatusOut {
    u32 version;
    u32 size;
    u64 client_id;
    u32 generation;
    u32 load_success;
    u32 registration_ready;
    u32 virtualization_ready;
    HvStatus status;
    HvProviderKind provider;
    u32 reserved;
};

#pragma pack(pop)

constexpr bool IsVersionedBufferValid(u32 version, u32 size,
                                      u32 required_size) {
    return version >= kAbiMinVersion && version <= kAbiVersion &&
           size >= required_size;
}

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::HvCapabilitySnapshot) == 56,
              "capability snapshot ABI changed");
static_assert(sizeof(knhv::HvProviderRegistration) == 80,
              "provider registration ABI changed");
static_assert(sizeof(knhv::HvProviderRequest) == 32,
              "provider request ABI changed");
static_assert(sizeof(knhv::HvQueryCapsIn) == 16,
              "query input ABI changed");
static_assert(sizeof(knhv::HvSessionKey) == 16,
              "session key ABI changed");
static_assert(sizeof(knhv::HvQuerySessionIn) == 32,
              "query session input ABI changed");
static_assert(sizeof(knhv::HvQueryCapsOut) == 80,
              "query output ABI changed");
static_assert(sizeof(knhv::HvSessionStatusOut) == 48,
              "session output ABI changed");
static_assert(sizeof(knhv::HvRegisterClientIn) == 96,
              "register input ABI changed");
static_assert(sizeof(knhv::HvRegisterClientOut) == 56,
              "register output ABI changed");
#endif
