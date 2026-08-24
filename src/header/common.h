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
// these offsets belong to this software frame, not to CPU-specific VMCS fields
// HvVmExitEntryPoint reserves the first 0x1000 bytes for XSAVE and starts the
// GPR/GuestContext fields at offset 0x1000. Keep the limit in a shared header
// so a future capability gate cannot silently overwrite the saved registers.
constexpr u64 VMEXIT_XSAVE_MAX = 0x1000;
constexpr u64 VMEXIT_FRAME_SIZE = 0x1180;
constexpr u64 VMEXIT_HOST_XCR0_OFFSET = 0x1168;
constexpr u64 VMEXIT_HOST_XSS_OFFSET = 0x1170;
constexpr u64 VMEXIT_HOST_KGS_OFFSET = 0x1178;
constexpr u64 VMEXIT_HOST_DR7_OFFSET = 0x1158;
constexpr u64 VMEXIT_HOST_DEBUGCTL_OFFSET = 0x1160;
static_assert(VMEXIT_XSAVE_MAX <= VMEXIT_FRAME_SIZE, "XSAVE frame exceeds VM-exit frame");
static_assert(VMEXIT_HOST_XCR0_OFFSET + sizeof(u64) <= VMEXIT_FRAME_SIZE,
              "host XCR0 slot exceeds VM-exit frame");
static_assert(VMEXIT_HOST_XSS_OFFSET + sizeof(u64) <= VMEXIT_FRAME_SIZE,
              "host XSS slot exceeds VM-exit frame");
static_assert(VMEXIT_HOST_KGS_OFFSET + sizeof(u64) == VMEXIT_FRAME_SIZE,
              "host KGS slot must terminate VM-exit frame");
static_assert(VMEXIT_HOST_DR7_OFFSET + sizeof(u64) <= VMEXIT_FRAME_SIZE,
              "host DR7 slot exceeds VM-exit frame");
static_assert(VMEXIT_HOST_DEBUGCTL_OFFSET + sizeof(u64) <= VMEXIT_FRAME_SIZE,
              "host DEBUGCTL slot exceeds VM-exit frame");
// Returned by GuestStartThunk after a successful VM-entry.  A distinct value
// lets the C++ launch callback distinguish the normal guest continuation from
// a VMLAUNCH failure (which returns VMX flags instead).
constexpr u64 VMX_LAUNCH_SUCCESS_MAGIC = 0x4C41554E43484544ULL; // "LAUNCHED"
// Returned by the defensive launch guard when CR4.VMXE is already clear. The
// caller must not interpret this value as VMX instruction flags.
constexpr u64 VMX_LAUNCH_NOT_VMX_MAGIC = 0xBAD0000000000001ULL;

enum VcpuState : long {
    VcpuUninitialized = 0,
    VcpuStarting      = 1,
    VcpuVmxOn         = 2,
    VcpuLaunched      = 3,
    VcpuStopped       = 4,
    VcpuFailed        = 5,
    // Fatal VM-exit/restore path parked this processor after VMXOFF.  Its
    // host stack and the driver image must remain resident.
    VcpuParked        = 6,
    // native teardown has left the guest path and is completing VMXOFF
    VcpuTearingDown   = 7,
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

    // XCR0 is not part of VMCS state.  The VM-exit stub records it before
    // switching the processor back to the host XCR0.  IA32_XSS is likewise
    // per-logical-processor state and is switched around XSAVES/XRSTORS.
    u64 GuestXcr0;
    u64 GuestXss;

    // Supervisor CET state is carried by VMCS fields, not by XSAVES.  Keep a
    // software copy for the VMXOFF teardown path and for trapped MSR writes.
    u64 GuestSCet;
    u64 GuestSsp;
    u64 GuestInterruptSspTable;
    u64 GuestDr7;
    u64 GuestDebugctl;
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
static_assert(offsetof(GuestContext, GuestXcr0) == 0x1108, "VM-exit XCR0 layout changed");
static_assert(offsetof(GuestContext, GuestXss) == 0x1110, "VM-exit XSS layout changed");
static_assert(offsetof(GuestContext, GuestSCet) == 0x1118, "VM-exit S_CET layout changed");
static_assert(offsetof(GuestContext, GuestSsp) == 0x1120, "VM-exit SSP layout changed");
static_assert(offsetof(GuestContext, GuestInterruptSspTable) == 0x1128,
              "VM-exit interrupt SSP table layout changed");
static_assert(offsetof(GuestContext, GuestDr7) == 0x1130,
              "VM-exit DR7 layout changed");
static_assert(offsetof(GuestContext, GuestDebugctl) == 0x1138,
              "VM-exit DEBUGCTL layout changed");
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
    // Capability profile selected for this logical processor.  The assembly
    // save contract is global, so mixed profiles are rejected before VMXON.
    u32   VmxProfile;
    volatile long VmcsWriteFailed;
    volatile long VmcsReadFailed;
    volatile long VmcsSetupPhase;
    u64   FirstVmcsWriteField;
    u64   FirstVmcsWriteFlags;
    u64   FirstVmcsWriteError;
    u64   FirstVmcsReadField;
    u64   FirstVmcsReadFlags;
    u64   LastVmclearFlags;
    u64   LastVmptrldFlags;
    u64   PrimaryControlsCapability;
    u64   TertiaryControlsAllowed;

    // IA32_KERNEL_GS_BASE is not part of VMCS state and SWAPGS does not cause
    // a VM-exit. Keep the guest GS/KGS values in software so the exit path can
    // restore both architectural values without inferring SWAPGS parity.
    u64   GuestGsBase;
    u64   GuestKernelGsBase;

    // Guest IA32_XSS/XCR0 are kept per virtual CPU because neither register
    // is represented by the VMCS.  The assembly entry/exit path switches the
    // hardware values around the C++ handler.
    u64   GuestXss;
    u64   GuestXcr0;
    u64   HostXss;
    u64   HostDr7;
    u64   HostDebugctl;
    u64   GuestDr7;
    u64   GuestDebugctl;
    // Native teardown is safe only while the guest still uses the descriptor
    // tables and segment selectors that were active at launch.  VMX restores
    // the host tables on exit, so a changed guest table cannot be IRETed back
    // without an explicit table-switch contract.
    u64   HostSegmentSelectorsLow;
    u64   HostSegmentSelectorsHigh;
    u64   HostGdtBase;
    u64   HostIdtBase;
    u64   HostTrBase;
    u64   HostGdtLimit;
    u64   HostIdtLimit;
    u64   HostTrLimit;
    u64   HostTrAr;
    u64   HostCsLimit;
    u64   HostSsLimit;
    u64   HostCsAr;
    u64   HostSsAr;
    volatile long NativeTeardownSafe;

    // State is published with InterlockedExchange so lifecycle callbacks can
    // inspect it without taking a lock at IPI_LEVEL.
    volatile long State;

    // XCR0 is not part of VMCS guest/host state.  XSETBV in VMX non-root can
    // otherwise change the mask used by the VM-exit XSAVE prologue while the
    // C++ handler is running.  Capture the root mask at launch and only
    // permit a guest XSETBV that leaves it unchanged; a different request is
    // turned into #GP instead of touching host XCR0.
    u64   HostXcr0;

    // Diagnostic counters are kept per logical processor so the VM-exit path
    // can report the first failures without flooding the kernel debugger.
    volatile long VmExitCount;

    // These fields are a passive-level diagnostic snapshot.  They are written
    // by the owning processor and read only after an IPI rendezvous completes.
    volatile long LaunchStage;
    volatile long LastExitReason;
    volatile u32 LastExitReasonRaw;
    volatile u32 LastExitReasonBasic;
    volatile u32 LastExitEntryFailure;
    volatile u64 LastLaunchFlags;
    volatile u64 LastVmResumeFlags;
    volatile long LastExitAction;
    volatile long VmResumeAttempts;
    u64 LastExitInstructionLength;
    u64 LastExitQualification;
    u64 LastGuestRip;
    u64 LastGuestRsp;
    u64 LastRflags;
    u64 LastGuestCr0;
    u64 LastGuestCr3;
    u64 LastGuestCr4;
    u64 LastGuestCs;
    u64 LastGuestSs;
    u64 LastGuestTr;
    u32 LastGuestCsAr;
    u32 LastGuestSsAr;
    u32 LastGuestTrAr;
    u32 LastGuestInterruptibility;
    u32 LastGuestActivity;
    u32 LastVmExitIntrInfo;
    u32 LastVmExitIntrError;
    u32 LastIdtVectoringInfo;
    u32 LastIdtVectoringError;
    u64 LastGuestDr7;
    u64 LastGuestDebugctl;
    u64 LastGuestEfer;
    u64 LastGuestPat;
    u64 LastGuestXcr0;
    u64 LastGuestXss;
    u64 LastGuestSCet;
    u64 LastGuestSsp;
    u64 LastGuestInterruptSspTable;
    u64 LastVmInstructionError;
};
