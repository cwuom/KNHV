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
// v1 remains the wire format used by existing clients. v2 is additive and
// is negotiated explicitly so an old client never interprets a lease as a
// v1 session response
constexpr u32 kAbiV2Version = 2U;
constexpr u32 kAbiV2MinVersion = 2U;
constexpr u32 kAbiV2MaxStructSize = 4096U;

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

// v2 separates hardware capability, provider capability and policy. A bit
// in one group must not be silently promoted into another group
constexpr u64 kPolicyExclusiveOwner = 1ULL << 0;
constexpr u64 kPolicyWindowsHandoff = 1ULL << 1;
constexpr u64 kPolicyNoPhysicalDma = 1ULL << 2;
constexpr u64 kPolicySyntheticOnly = 1ULL << 3;
constexpr u64 kKnownPolicyFeatureMask = (1ULL << 4) - 1ULL;

constexpr u32 kRequestFlagRequireExclusive = 1U << 0;
constexpr u32 kRequestFlagReadOnly = 1U << 1;
constexpr u32 kKnownV2RequestFlagMask =
    kRequestFlagRequireExclusive | kRequestFlagReadOnly;

constexpr u32 kLeaseFlagExclusive = 1U << 0;
constexpr u32 kLeaseFlagSynthetic = 1U << 1;
constexpr u32 kLeaseFlagReadOnly = 1U << 2;
constexpr u32 kKnownV2LeaseFlagMask =
    kLeaseFlagExclusive | kLeaseFlagSynthetic | kLeaseFlagReadOnly;

enum class HvOwnerKindV2 : u32 {
    Unknown = 0,
    ExternalL0 = 1,
    KnhvBootL0 = 2,
    WhpManaged = 3,
    SyntheticLab = 4,
};

enum class HvProviderStateV2 : u32 {
    Unknown = 0,
    Available = 1,
    Active = 2,
    Conflict = 3,
    Blocked = 4,
    Quarantined = 5,
};

enum class HvLeaseModeV2 : u32 {
    None = 0,
    HardwareL0 = 1,
    WhpManaged = 2,
    SyntheticLab = 3,
};

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

// v2 structures use size first to make the extension boundary obvious in a
// debugger and keep the generation attached to every capability or lease
struct HvCapabilitySnapshotV2 {
    u32 size;
    u32 version;
    u64 hardware_features;
    u64 provider_features;
    u64 policy_features;
    u32 owner_kind;
    u32 state;
    u64 generation;
};

struct HvOwnerLeaseV2 {
    u32 size;
    u32 version;
    u64 owner_id;
    u64 generation;
    u32 mode;
    u32 flags;
};

struct HvProviderRequestV2 {
    u32 size;
    u32 version;
    u64 request_id;
    HvSessionKey session;
    u64 required_hardware_features;
    u64 required_provider_features;
    u64 required_policy_features;
    u32 mode;
    u32 flags;
};

struct HvProviderResponseV2 {
    u32 size;
    u32 version;
    u64 request_id;
    HvStatus status;
    u32 reserved;
    HvProviderKind provider;
    u32 reserved2;
    HvCapabilitySnapshotV2 capabilities;
    HvOwnerLeaseV2 lease;
};

struct HvQueryCapsV2In {
    u32 size;
    u32 version;
    u64 request_id;
};

struct HvQueryCapsV2Out {
    u32 size;
    u32 version;
    u64 request_id;
    HvStatus status;
    u32 reserved;
    HvCapabilitySnapshotV2 capabilities;
};

struct HvAcquireLeaseV2In {
    u32 size;
    u32 version;
    HvProviderRequestV2 request;
};

struct HvAcquireLeaseV2Out {
    u32 size;
    u32 version;
    HvProviderResponseV2 response;
};

struct HvReleaseLeaseV2In {
    u32 size;
    u32 version;
    u64 request_id;
    HvSessionKey session;
    HvOwnerLeaseV2 lease;
};

struct HvReleaseLeaseV2Out {
    u32 size;
    u32 version;
    u64 request_id;
    HvStatus status;
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

constexpr bool IsAbiV2BufferValid(u32 version, u32 size,
                                  u32 required_size) {
    return version >= kAbiV2MinVersion && version <= kAbiV2Version &&
           size >= required_size && size <= kAbiV2MaxStructSize;
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
static_assert(sizeof(knhv::HvCapabilitySnapshotV2) == 48,
              "v2 capability snapshot ABI changed");
static_assert(sizeof(knhv::HvOwnerLeaseV2) == 32,
              "v2 owner lease ABI changed");
static_assert(sizeof(knhv::HvProviderRequestV2) == 64,
              "v2 provider request ABI changed");
static_assert(sizeof(knhv::HvProviderResponseV2) == 112,
              "v2 provider response ABI changed");
static_assert(sizeof(knhv::HvQueryCapsV2In) == 16,
              "v2 query input ABI changed");
static_assert(sizeof(knhv::HvQueryCapsV2Out) == 72,
              "v2 query output ABI changed");
static_assert(sizeof(knhv::HvAcquireLeaseV2In) == 72,
              "v2 acquire input ABI changed");
static_assert(sizeof(knhv::HvAcquireLeaseV2Out) == 120,
              "v2 acquire output ABI changed");
static_assert(sizeof(knhv::HvReleaseLeaseV2In) == 64,
              "v2 release input ABI changed");
static_assert(sizeof(knhv::HvReleaseLeaseV2Out) == 24,
              "v2 release output ABI changed");
#endif
