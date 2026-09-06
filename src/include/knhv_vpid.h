#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kVpidContractVersion = 1U;
constexpr u32 kVpidMaxStructSize = 4096U;
constexpr u32 kVpidMinimum = 1U;
constexpr u32 kVpidMaximum = 0xFFFFU;
constexpr u32 kVpidMaxLeases = 128U;
constexpr u32 kVpidMaxCpus = 64U;

// the lease itself carries no caller-controlled flags yet. Keeping an
// explicit mask makes future extensions fail closed for older consumers
constexpr u32 kVpidKnownLeaseFlagMask = 0U;

constexpr u32 kShootdownAllowAllContext = 1U << 0;
constexpr u32 kShootdownRetainGlobals = 1U << 1;
constexpr u32 kShootdownKnownFlagMask =
    kShootdownAllowAllContext | kShootdownRetainGlobals;

enum class VpidKind : u32 {
    Root = 1,
    L1 = 2,
    L2 = 3,
};

enum class VpidLeaseState : u32 {
    Free = 0,
    Active = 1,
    Retiring = 2,
    Quarantined = 3,
};

enum class VpidStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    Exhausted = 2,
    GenerationMismatch = 3,
    Conflict = 4,
    StateConflict = 5,
    ShootdownIncomplete = 6,
    Timeout = 7,
    Quarantined = 8,
};

enum class ShootdownType : u32 {
    // values match the Intel INVVPID descriptor type encoding
    SingleAddress = 0,
    SingleContext = 1,
    AllContext = 2,
    SingleContextRetainGlobals = 3,
};

enum class ShootdownStateKind : u32 {
    Idle = 0,
    Pending = 1,
    Completed = 2,
    TimedOut = 3,
    Quarantined = 4,
};

#pragma pack(push, 8)

struct VpidRequest {
    u32 size;
    u32 version;
    u64 owner_id;
    u64 generation;
    u32 kind;
    u32 max_vpid;
    u32 reserved;
    u32 reserved2;
};

struct VpidLease {
    u32 size;
    u32 version;
    u32 vpid;
    u32 kind;
    u32 state;
    u32 flags;
    u64 owner_id;
    u64 generation;
    u64 allocation_sequence;
};

struct ShootdownRequest {
    u32 size;
    u32 version;
    u32 type;
    u32 flags;
    u64 request_id;
    u64 generation;
    u32 source_cpu;
    u32 vpid;
    u64 target_cpu_mask;
    u64 address;
    u64 deadline_tsc;
};

struct ShootdownState {
    u32 size;
    u32 version;
    u32 type;
    u32 state;
    u64 request_id;
    u64 generation;
    u64 target_cpu_mask;
    u64 acknowledged_cpu_mask;
    u64 deadline_tsc;
    u32 vpid;
    u32 reserved;
};

#pragma pack(pop)

bool IsVpidRequestValid(const VpidRequest* request);
bool IsVpidLeaseValid(const VpidLease* lease);
VpidStatus AllocateVpid(const VpidRequest* request,
                        const VpidLease* existing, u32 existing_count,
                        VpidLease* lease);
bool BeginVpidRetire(VpidLease* lease, u64 generation);
bool ReclaimVpid(VpidLease* lease, u64 generation,
                 const ShootdownState* shootdown);
bool QuarantineVpid(VpidLease* lease, u64 generation);

bool IsShootdownRequestValid(const ShootdownRequest* request);
bool IsShootdownStateValid(const ShootdownState* state);
bool BeginShootdown(const ShootdownRequest* request, ShootdownState* state);
bool AcknowledgeShootdown(ShootdownState* state, u32 cpu_index);
bool CompleteShootdown(ShootdownState* state, u64 now_tsc);
bool QuarantineShootdown(ShootdownState* state);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::VpidRequest) == 40,
              "VPID request ABI changed");
static_assert(sizeof(knhv::VpidLease) == 48,
              "VPID lease ABI changed");
static_assert(sizeof(knhv::ShootdownRequest) == 64,
              "shootdown request ABI changed");
static_assert(sizeof(knhv::ShootdownState) == 64,
              "shootdown state ABI changed");
#endif
