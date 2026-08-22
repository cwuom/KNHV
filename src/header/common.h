//
// Created by cwuom on 17 Feb 2026.
//

#pragma once

#include <cstddef>

using u64 = unsigned __int64;
using u32 = unsigned __int32;
using u16 = unsigned __int16;
using u8  = unsigned __int8;

// constants
constexpr u64 HYPERVISOR_MAGIC = 0x13371337;
constexpr u64 VMCALL_UNLOAD    = 0xDEADBEEF;
// HvVmExitEntryPoint reserves the first 0x1000 bytes for XSAVE and starts the
// GPR/GuestContext fields at offset 0x1000. Keep the limit in a shared header
// so a future capability gate cannot silently overwrite the saved registers.
constexpr u64 VMEXIT_XSAVE_MAX = 0x1000;
// Returned by GuestStartThunk after a successful VM-entry.  A distinct value
// lets the C++ launch callback distinguish the normal guest continuation from
// a VMLAUNCH failure (which returns VMX flags instead).
constexpr u64 VMX_LAUNCH_SUCCESS_MAGIC = 0x4C41554E43484544ULL; // "LAUNCHED"

enum VcpuState : long {
    VcpuUninitialized = 0,
    VcpuVmxOn         = 1,
    VcpuLaunched      = 2,
    VcpuStopped       = 3,
    VcpuFailed        = 4,
    // Fatal VM-exit/restore path parked this processor after VMXOFF.  Its
    // host stack and the driver image must remain resident.
    VcpuParked        = 5,
};

struct __declspec(align(64)) GuestContext {
    // The VM-exit stub saves the complete architectural XSAVE area first and
    // then the GPRs at the fixed offsets below.  Keep this buffer large enough
    // for the XCR0 state used by supported Windows kernels; StartHypervisor()
    // rejects a machine whose CPUID-reported area does not fit.
    u8 FxArea[4096];

    u64 Rax; u64 Rcx; u64 Rdx; u64 Rbx; u64 Rbp;
    u64 Rsi; u64 Rdi; u64 R8;  u64 R9;  u64 R10;
    u64 R11; u64 R12; u64 R13; u64 R14; u64 R15;

    u64 GuestRip;
    u64 GuestRsp;
    u64 Rflags;

    // State needed by the fail-safe VMXOFF/IRET path.  In particular, using
    // the current host CS/SS when the guest was at CPL3 creates an invalid
    // return frame and is a common source of triple faults.
    u64 GuestCs;
    u64 GuestSs;
    u64 GuestCr3;
    u64 GuestCr4;
    u64 GuestFsBase;
    u64 GuestGsBase;
    u64 GuestEfer;
    u64 GuestPat;
    // IA32_KERNEL_GS_BASE is not a VMCS field.  VMX therefore leaves it
    // untouched across VM-exit/entry; save it explicitly so a guest SWAPGS
    // cannot poison the host's per-CPU GS state on Windows.
    u64 GuestKernelGsBase;
    u64 AbortVm;
    u64 HaltVm;
    u64 GuestCr0;
    // VMX loads the guest SYSENTER MSRs on every VM-entry and the host copies
    // are loaded on every VM-exit.  Keep software copies so trapped WRMSR
    // operations and the VMXOFF teardown path preserve the guest values.
    u64 GuestSysenterCs;
    u64 GuestSysenterEsp;
    u64 GuestSysenterEip;
};

static_assert(offsetof(GuestContext, Rax) == 0x1000, "VM-exit GPR layout changed");
static_assert(offsetof(GuestContext, GuestRip) == 0x1078, "VM-exit RIP layout changed");
static_assert(offsetof(GuestContext, GuestRsp) == 0x1080, "VM-exit RSP layout changed");
static_assert(offsetof(GuestContext, Rflags) == 0x1088, "VM-exit RFLAGS layout changed");
static_assert(offsetof(GuestContext, GuestCs) == 0x1090, "VM-exit CS layout changed");
static_assert(offsetof(GuestContext, GuestSs) == 0x1098, "VM-exit SS layout changed");
static_assert(offsetof(GuestContext, GuestCr3) == 0x10A0, "VM-exit CR3 layout changed");
static_assert(offsetof(GuestContext, GuestCr4) == 0x10A8, "VM-exit CR4 layout changed");
static_assert(offsetof(GuestContext, GuestFsBase) == 0x10B0, "VM-exit FS layout changed");
static_assert(offsetof(GuestContext, GuestGsBase) == 0x10B8, "VM-exit GS layout changed");
static_assert(offsetof(GuestContext, GuestEfer) == 0x10C0, "VM-exit EFER layout changed");
static_assert(offsetof(GuestContext, GuestPat) == 0x10C8, "VM-exit PAT layout changed");
static_assert(offsetof(GuestContext, GuestKernelGsBase) == 0x10D0, "VM-exit KernelGS layout changed");
static_assert(offsetof(GuestContext, AbortVm) == 0x10D8, "VM-exit abort layout changed");
static_assert(offsetof(GuestContext, HaltVm) == 0x10E0, "VM-exit halt layout changed");
static_assert(offsetof(GuestContext, GuestCr0) == 0x10E8, "VM-exit CR0 layout changed");
static_assert(offsetof(GuestContext, GuestSysenterCs) == 0x10F0, "VM-exit SYSENTER CS layout changed");
static_assert(offsetof(GuestContext, GuestSysenterEsp) == 0x10F8, "VM-exit SYSENTER ESP layout changed");
static_assert(offsetof(GuestContext, GuestSysenterEip) == 0x1100, "VM-exit SYSENTER EIP layout changed");
// The VM-exit frame is 0x1180 bytes.  Its final eight bytes are reserved for
// the per-CPU host KERNEL_GS_BASE shadow (HostStackTop - 8).
static_assert(offsetof(GuestContext, GuestSysenterEip) + sizeof(u64) <= 0x1178,
              "VM-exit fields overlap host KGS slot");
static_assert(sizeof(GuestContext) <= 0x1178, "VM-exit frame would overlap host KGS slot");

struct VcpuContext {
    // physical/virtual pairs for VMX structures
    u64   VmxOnPhys;
    void* VmxOnVirt;

    u64   VmcsPhys;
    void* VmcsVirt;

    u64   MsrBitmapPhys;
    void* MsrBitmapVirt;

    void* HostStack;
    u64   HostStackTop;

    // Per-CPU host state and VMX revision.  These values must be obtained on
    // the logical processor that executes VMXON; VMX capability MSRs are not
    // required to be identical across heterogeneous Intel packages.
    u64   HostCr3;
    u64   OriginalCr0;
    u64   OriginalCr4;
    u64   VmxBasic;
    u32   RevisionId;
    u32   Reserved;
    volatile long VmcsWriteFailed;

    // IA32_KERNEL_GS_BASE is not part of VMCS state and SWAPGS does not cause
    // a VM-exit. Keep the guest GS/KGS pair in software so the exit path can
    // detect an odd SWAPGS and repair GUEST_GS_BASE before VMRESUME.
    u64   GuestGsBase;
    u64   GuestKernelGsBase;

    // 0 = uninitialized, 1 = VMXON, 2 = guest launched, 3 = stopped,
    // 4 = failed.  LONG is used so the IPI callbacks can publish state with
    // InterlockedExchange at DISPATCH_LEVEL.
    volatile long State;

    // XCR0 is not part of VMCS guest/host state.  XSETBV in VMX non-root can
    // otherwise change the mask used by the VM-exit XSAVE prologue while the
    // C++ handler is running.  Capture the root mask at launch and only
    // permit a guest XSETBV that leaves it unchanged; a different request is
    // turned into #GP instead of touching host XCR0.
    u64   HostXcr0;
};
