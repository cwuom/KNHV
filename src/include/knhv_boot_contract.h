#pragma once

#include "knhv_abi.h"

namespace knhv {

enum class BootL0State : u32 {
    PreL0 = 0,
    RootActive = 1,
    WindowsHandoff = 2,
    Ready = 3,
    Recovery = 4,
};

struct BootContext {
    u32 version;
    u32 size;
    u32 logical_processors;
    u32 manifest_valid;
    u32 physical_vmx_ready;
    u32 external_owner;
    u32 windows_handoff_ready;
    u32 reserved;
};

struct BootOwnerToken {
    u64 nonce;
    u32 generation;
    u32 owner_count;
    u32 active_processors;
    u32 reserved;
};

struct BootEvidence {
    u32 version;
    u32 size;
    BootL0State state;
    u32 boot_generation;
    u32 owner_generation;
    u32 owner_count;
    u32 active_processors;
    HvStatus last_status;
};

struct BootL0Contract {
    u32 version;
    u32 size;
    BootL0State state;
    u32 generation;
    BootOwnerToken owner;
    BootEvidence evidence;
};

void InitializeBootL0Contract(BootL0Contract* contract);
HvStatus StartBootL0(BootL0Contract* contract, const BootContext* context);
HvStatus HandoffWindows(BootL0Contract* contract, const BootContext* context);
HvStatus RecoverBootL0(BootL0Contract* contract, HvStatus reason);
HvStatus StopBootL0(BootL0Contract* contract);

}  // namespace knhv
