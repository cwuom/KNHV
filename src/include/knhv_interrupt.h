#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kInterruptContractVersion = 1U;
constexpr u32 kInterruptMaxStructSize = 4096U;
constexpr u32 kInterruptQueueDepth = 32U;
constexpr u32 kInterruptVectorCount = 256U;
constexpr u32 kInterruptVectorFirstExternal = 32U;

constexpr u32 kInterruptBlockBySti = 1U << 0;
constexpr u32 kInterruptBlockByMovSs = 1U << 1;
constexpr u32 kInterruptBlockNmi = 1U << 2;
constexpr u32 kInterruptKnownBlockMask =
    kInterruptBlockBySti | kInterruptBlockByMovSs | kInterruptBlockNmi;

constexpr u32 kInterruptEventDeliverError = 1U << 0;
constexpr u32 kInterruptEventPosted = 1U << 1;
constexpr u32 kInterruptEventFromDevice = 1U << 2;
constexpr u32 kInterruptKnownEventMask =
    kInterruptEventDeliverError | kInterruptEventPosted |
    kInterruptEventFromDevice;

enum class InterruptKind : u32 {
    HardwareException = 0,
    External = 1,
    Nmi = 2,
    Virtual = 3,
    Init = 4,
    Sipi = 5,
    Smi = 6,
};

enum class InterruptStatus : u32 {
    Ready = 0,
    NoPending = 1,
    Blocked = 2,
    Invalid = 3,
    GenerationMismatch = 4,
    QueueFull = 5,
    Conflict = 6,
};

enum class InterruptAction : u32 {
    Inject = 0,
    WaitWindow = 1,
    Quarantine = 2,
};

#pragma pack(push, 8)

struct InterruptEvent {
    u32 size;
    u32 version;
    u32 kind;
    u32 vector;
    u32 error_code;
    u32 flags;
    u32 reserved;
    u32 reserved2;
    u64 source_id;
    u64 generation;
    u64 sequence;
};

struct InterruptState {
    u32 size;
    u32 version;
    u64 generation;
    u64 next_sequence;
    u32 pending_count;
    u32 interruptibility;
    u32 virtual_apic_tpr;
    u32 reserved;
    InterruptEvent pending[kInterruptQueueDepth];
};

struct InterruptDecision {
    u32 size;
    u32 version;
    u32 status;
    u32 action;
    u32 kind;
    u32 vector;
    u32 error_code;
    u32 flags;
    u32 reserved;
    u32 reserved2;
    u64 sequence;
    u64 generation;
};

struct PostedInterruptDescriptor {
    u32 size;
    u32 version;
    u32 notification_vector;
    u32 suppress_notification;
    u32 reserved;
    u32 reserved2;
    u32 pir[8];
    u64 generation;
};

#pragma pack(pop)

bool IsInterruptEventValid(const InterruptEvent* event);
bool IsInterruptStateValid(const InterruptState* state);
InterruptStatus EnqueueInterrupt(InterruptState* state,
                                  const InterruptEvent* event);
InterruptStatus SelectInterrupt(const InterruptState* state,
                                 u64 generation,
                                 InterruptDecision* decision);
bool CommitInterruptInjection(InterruptState* state,
                              const InterruptDecision* decision);

bool IsPostedInterruptValid(const PostedInterruptDescriptor* descriptor);
bool PostInterrupt(PostedInterruptDescriptor* descriptor, u32 vector,
                   u64 generation);
InterruptStatus DrainPostedInterrupt(PostedInterruptDescriptor* descriptor,
                                      InterruptState* state,
                                      u64 generation, u64 source_id);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::InterruptEvent) == 56,
              "interrupt event ABI changed");
static_assert(sizeof(knhv::InterruptState) == 1832,
              "interrupt state ABI changed");
static_assert(sizeof(knhv::InterruptDecision) == 56,
              "interrupt decision ABI changed");
static_assert(sizeof(knhv::PostedInterruptDescriptor) == 64,
              "posted interrupt ABI changed");
#endif
