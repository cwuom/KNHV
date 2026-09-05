#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kEptContractVersion = 1U;
constexpr u32 kEptMaxStructSize = 4096U;
constexpr u32 kEptPageShift = 12U;
constexpr u32 kEptPageSize = 1U << kEptPageShift;
constexpr u32 kEptMaxPhysicalAddressBits = 52U;
constexpr u32 kEptMinWalkLength = 4U;
constexpr u32 kEptMaxWalkLength = 5U;
constexpr u32 kEptMemoryTypeUc = 0U;
constexpr u32 kEptMemoryTypeWb = 6U;

constexpr u32 kEptpFlagAccessDirty = 1U << 0;
constexpr u32 kEptpKnownFlagMask = kEptpFlagAccessDirty;

constexpr u32 kEptMappingFlagPresent = 1U << 0;
constexpr u32 kEptMappingFlagLargePage = 1U << 1;
constexpr u32 kEptMappingFlagAccessDirty = 1U << 2;
constexpr u32 kEptMappingFlagHostOwned = 1U << 3;
constexpr u32 kEptMappingKnownFlagMask =
    kEptMappingFlagPresent | kEptMappingFlagLargePage |
    kEptMappingFlagAccessDirty | kEptMappingFlagHostOwned;

constexpr u32 kEptPermissionRead = 1U << 0;
constexpr u32 kEptPermissionWrite = 1U << 1;
constexpr u32 kEptPermissionExecute = 1U << 2;
constexpr u32 kEptPermissionKnownMask = kEptPermissionRead |
                                         kEptPermissionWrite |
                                         kEptPermissionExecute;
constexpr u32 kEptMaxMappingPages = 1U << 20;

enum class EptAccess : u32 {
    Read = 1,
    Write = 2,
    Execute = 3,
};

enum class EptViewKind : u32 {
    RootNative = 1,
    GuestRuntime = 2,
    GuestDebug = 3,
};

enum class EptHookKind : u32 {
    Execute = 1,
    Read = 2,
    Write = 3,
    Access = 4,
    Monitor = 5,
};

enum class EptLookupStatus : u32 {
    Hit = 0,
    NotPresent = 1,
    PermissionDenied = 2,
    Stale = 3,
    Invalid = 4,
    HostOwned = 5,
};

enum class EptHookState : u32 {
    Active = 1,
    Expired = 2,
    Revoked = 3,
    Quarantined = 4,
};

enum class EptGenerationState : u32 {
    Active = 1,
    Pending = 2,
    Retired = 3,
    Quarantined = 4,
};

#pragma pack(push, 8)

struct EptpConfig {
    u32 size;
    u32 version;
    u64 root_physical;
    u32 memory_type;
    u32 walk_length;
    u32 flags;
    u32 reserved;
    u64 generation;
};

struct EptMapping {
    u32 size;
    u32 version;
    u64 guest_physical;
    u64 host_physical;
    u64 page_count;
    u32 page_order;
    u32 permissions;
    u32 memory_type;
    u32 flags;
    u64 generation;
};

struct EptLookupResult {
    u32 size;
    u32 version;
    u32 status;
    u32 permissions;
    u64 host_physical;
    u64 generation;
};

struct EptHookLease {
    u32 size;
    u32 version;
    u64 owner_id;
    u64 generation;
    u64 expires_tsc;
    u32 view;
    u32 hook_kind;
    u32 state;
    u32 max_pages;
    u32 max_exits_per_second;
    u32 reserved;
};

struct EptHookRequest {
    u32 size;
    u32 version;
    u64 owner_id;
    u64 expected_generation;
    u64 guest_physical;
    u64 page_count;
    u32 view;
    u32 hook_kind;
    u32 permissions;
    u32 reserved;
    u64 module_hash[2];
};

struct EptGeneration {
    u32 size;
    u32 version;
    u64 generation;
    u64 parent_generation;
    u32 state;
    u32 required_cpu_acks;
    u32 observed_cpu_acks;
    u32 reserved;
};

#pragma pack(pop)

bool IsEptpConfigValid(const EptpConfig* config, u32 max_physical_bits);
bool BuildEptPointer(const EptpConfig* config, u64* raw_eptp);
bool DecodeEptPointer(u64 raw_eptp, EptpConfig* config);
bool IsEptMappingValid(const EptMapping* mapping, u32 max_physical_bits);
bool EptMappingContains(const EptMapping* mapping, u64 guest_physical);
bool IsEptAccessAllowed(u32 permissions, EptAccess access);

EptLookupResult ResolveNestedEpt(const EptMapping* l1_mapping,
                                 const EptMapping* root_mapping,
                                 u64 l2_guest_physical, EptAccess access);

bool IsEptHookLeaseValid(const EptHookLease* lease);
bool IsEptHookRequestValid(const EptHookRequest* request);
bool CanPublishEptHook(const EptHookLease* lease,
                       const EptHookRequest* request,
                       u64 current_generation, u64 now_tsc);

bool NextEptGeneration(u64 current_generation, u64* next_generation);
bool BeginEptGeneration(const EptGeneration* current,
                        EptGeneration* pending);
bool AcknowledgeEptGeneration(EptGeneration* pending, u32 cpu_count);
bool PublishEptGeneration(EptGeneration* pending);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::EptpConfig) == 40,
              "EPTP configuration ABI changed");
static_assert(sizeof(knhv::EptMapping) == 56,
              "EPT mapping ABI changed");
static_assert(sizeof(knhv::EptLookupResult) == 32,
              "EPT lookup ABI changed");
static_assert(sizeof(knhv::EptHookLease) == 56,
              "EPT hook lease ABI changed");
static_assert(sizeof(knhv::EptHookRequest) == 72,
              "EPT hook request ABI changed");
static_assert(sizeof(knhv::EptGeneration) == 40,
              "EPT generation ABI changed");
#endif
