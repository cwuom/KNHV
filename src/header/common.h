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

// The recorder is allocated before VMX starts and is written from IPI/root
// paths without locks, allocation, formatting, or debugger output
constexpr u32 HV_TRACE_RECORDS_PER_CPU = 512;
constexpr u32 HV_TRACE_TAIL_RECORDS = 32;

struct HvTraceRecord {
    u64 Sequence;
    u64 Tsc;
    u32 Cpu;
    u16 Lifecycle;
    u16 Stage;
    u32 Event;
    u64 Arg0;
    u64 Arg1;
    u64 Arg2;
    u64 Arg3;
};

static_assert(sizeof(HvTraceRecord) == 64,
              "flight recorder records must remain fixed-size");

enum HvTraceEvent : u32 {
    HvTraceEventDriverEntry = 1,
    HvTraceEventContractBegin = 2,
    HvTraceEventContractOk = 3,
    HvTraceEventContractFail = 4,
    HvTraceEventCpuIpiEnter = 5,
    HvTraceEventPreVmxon = 6,
    HvTraceEventPostVmxon = 7,
    HvTraceEventPreVmclear = 8,
    HvTraceEventPostVmclear = 9,
    HvTraceEventPreVmptrld = 10,
    HvTraceEventPostVmptrld = 11,
    HvTraceEventVmcsControlsDone = 12,
    HvTraceEventVmcsHostDone = 13,
    HvTraceEventVmcsGuestDone = 14,
    HvTraceEventPreVmlaunch = 15,
    HvTraceEventVmlaunchFail = 16,
    HvTraceEventGuestStart = 17,
    HvTraceEventVmexitEntry = 18,
    HvTraceEventVmEntryFailure = 19,
    HvTraceEventPreVmresume = 20,
    HvTraceEventVmresumeFail = 21,
    HvTraceEventTeardownRequest = 22,
    HvTraceEventPreVmxoff = 23,
    HvTraceEventPostVmxoff = 24,
    HvTraceEventRollbackDone = 25,
    HvTraceEventFatalSnapshot = 26,
    HvTraceEventPreBugcheck = 27,
    HvTraceEventXssPreservationFail = 28,
    HvTraceEventFatalSnapshotComplete = 29,
    HvTraceEventFatalParked = 30,
    HvTraceEventFatalVmexit = 31,
    HvTraceEventFirstExitProbe = 32,
    HvTraceEventCr3LaunchContract = 33,
    HvTraceEventHostIdtReady = 34,
    HvTraceEventVmexitHostStateReady = 35,
    HvTraceEventPostDpcCanary = 36,
};

// first-wins VMX-root exception evidence. The assembly exception stubs fill
// the architectural prefix before calling any Windows routine so a recursive
// host fault still leaves a debugger-visible vector, RIP and control state.
struct HvHostFaultRecord {
    volatile u32 CommitState;
    u32 Vector;
    u64 ErrorCode;
    u64 Rip;
    u64 Rsp;
    u64 Rflags;
    u64 Cr2;
    u64 Cr3;
    u64 Cr4;
    u64 Tsc;
    volatile u32 Cpu;
    u32 Reserved;
    u64 LastExitReasonRaw;
    u64 LastGuestRip;
    u64 LastGuestRsp;
    u64 LastExitQualification;
    u64 LastIdtVectoringInfo;
    u64 LastVmExitIntrInfo;
    u64 VmExitCount;
    u64 LaunchStage;
    u64 LaunchCheckStage;
};

static_assert(offsetof(HvHostFaultRecord, CommitState) == 0x00,
              "host fault commit offset changed");
static_assert(offsetof(HvHostFaultRecord, Vector) == 0x04,
              "host fault vector offset changed");
static_assert(offsetof(HvHostFaultRecord, ErrorCode) == 0x08,
              "host fault error-code offset changed");
static_assert(offsetof(HvHostFaultRecord, Rip) == 0x10,
              "host fault RIP offset changed");
static_assert(offsetof(HvHostFaultRecord, Rsp) == 0x18,
              "host fault RSP offset changed");
static_assert(offsetof(HvHostFaultRecord, Rflags) == 0x20,
              "host fault RFLAGS offset changed");
static_assert(offsetof(HvHostFaultRecord, Cr2) == 0x28,
              "host fault CR2 offset changed");
static_assert(offsetof(HvHostFaultRecord, Cr3) == 0x30,
              "host fault CR3 offset changed");
static_assert(offsetof(HvHostFaultRecord, Cr4) == 0x38,
              "host fault CR4 offset changed");
static_assert(offsetof(HvHostFaultRecord, Tsc) == 0x40,
              "host fault TSC offset changed");
static_assert(offsetof(HvHostFaultRecord, Cpu) == 0x48,
              "host fault CPU offset changed");
static_assert(sizeof(HvHostFaultRecord) == 0x98,
              "host fault record layout changed");
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
constexpr u32 FXSAVE_AREA_SIZE = 512;
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

enum XstateSaveMode : u8 {
    XstateSaveFxsave = 0,
    XstateSaveXsave = 1,
    XstateSaveXsaves = 2,
};
// Returned by GuestStartThunk after a successful VM-entry.  A distinct value
// lets the C++ launch callback distinguish the normal guest continuation from
// a VMLAUNCH failure (which returns VMX flags instead).
constexpr u64 VMX_LAUNCH_SUCCESS_MAGIC = 0x4C41554E43484544ULL; // "LAUNCHED"
// Returned by the defensive launch guard when CR4.VMXE is already clear. The
// caller must not interpret this value as VMX instruction flags.
constexpr u64 VMX_LAUNCH_NOT_VMX_MAGIC = 0xBAD0000000000001ULL;
// Returned when the pre-entry lifecycle marker cannot publish VcpuLaunched.
// The launch wrapper must roll back VMX without interpreting this value as
// VMfailValid or VMfailInvalid flags.
constexpr u64 VMX_LAUNCH_MARKER_FAILURE_MAGIC = 0xBAD0000000000002ULL;

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

// VMCS ownership is tracked separately from the lifecycle state because a
// launch failure can leave VMX root active between two lifecycle updates
enum VmcsCurrentState : long {
    VmcsCurrentStateNone = 0,
    VmcsCurrentStateActive = 1,
    VmcsCurrentStateClearing = 2,
    VmcsCurrentStateFailed = 3,
};

// this first-wins record identifies why VMCS preparation stopped. The detailed
// field, flag, and mismatch tuples remain in the neighboring diagnostic fields
enum HvVmcsFailureReason : u32 {
    HvVmcsFailureNone = 0,
    HvVmcsFailureArgument = 1,
    HvVmcsFailureVmclear = 2,
    HvVmcsFailureVmptrld = 3,
    HvVmcsFailureCetWriteProtect = 4,
    HvVmcsFailureMsrSnapshot = 5,
    HvVmcsFailureGuestTr = 6,
    HvVmcsFailureDescriptorCr3 = 7,
    HvVmcsFailureLdtr = 8,
    HvVmcsFailureSampledTr = 9,
    HvVmcsFailureVmwrite = 10,
    HvVmcsFailureVmread = 11,
    HvVmcsFailureMismatch = 12,
    HvVmcsFailureGuestEntry = 13,
    HvVmcsFailureControlPolicy = 14,
    HvVmcsFailureXstatePolicy = 15,
    HvVmcsFailureInjected = 16,
    HvVmcsFailureReadback = 17,
    HvVmcsFailureException = 18,
};

enum HvVmcsFailureCommitState : long {
    HvVmcsFailureEmpty = 0,
    HvVmcsFailureWriting = 1,
    HvVmcsFailureCommitted = 2,
};

// Intel exposes a hybrid core type through CPUID leaf 1A. Keep the branch
// explicit so a VMX profile selected on a P-core is never silently reused as
// an assumption about an E-core or an older legacy processor.
enum IntelCpuBranch : u32 {
    IntelCpuBranchUnknown = 0,
    IntelCpuBranchLegacy = 1,
    IntelCpuBranchModern = 2,
    IntelCpuBranchHybridPerformance = 3,
    IntelCpuBranchHybridEfficient = 4,
    IntelCpuBranchHybridUnknown = 5,
};

enum HvFatalSnapshotCommitState : long {
    HvFatalSnapshotEmpty = 0,
    HvFatalSnapshotWriting = 1,
    HvFatalSnapshotCommitted = 2,
};

// these bits describe which VMCS values are meaningful in the software
// snapshot. Intel leaves most VM-exit fields unchanged on a VM-entry failure,
// so a zero value alone cannot distinguish a real zero from an unknown value
enum HvVmcsDiagnosticValidity : u64 {
    HvVmcsValidityNone = 0,
    HvVmcsValidityExitReason = 1ULL << 0,
    HvVmcsValidityExitQualification = 1ULL << 1,
    HvVmcsValidityExitInstructionLength = 1ULL << 2,
    HvVmcsValidityEventState = 1ULL << 3,
    HvVmcsValidityGuestState = 1ULL << 4,
    HvVmcsValidityVmInstructionError = 1ULL << 5,
    HvVmcsValidityVmcsReadFailure = 1ULL << 6,
    HvVmcsValidityVmcsReadback = 1ULL << 7,
};

// 记录原生拆除被拒绝的具体契约原因，供崩溃后的离线分析使用
enum HvNativeTeardownReject : u32 {
    HvNativeTeardownRejectNone = 0,
    HvNativeTeardownRejectSelector = 1U << 0,
    HvNativeTeardownRejectCsSsLimitAr = 1U << 1,
    HvNativeTeardownRejectGdt = 1U << 2,
    HvNativeTeardownRejectIdt = 1U << 3,
    HvNativeTeardownRejectTr = 1U << 4,
    HvNativeTeardownRejectVmEntryEvent = 1U << 5,
    HvNativeTeardownRejectExitEvent = 1U << 6,
    HvNativeTeardownRejectIdtVectoring = 1U << 7,
    HvNativeTeardownRejectActivity = 1U << 8,
    HvNativeTeardownRejectInterruptibility = 1U << 9,
    HvNativeTeardownRejectPendingDebug = 1U << 10,
    HvNativeTeardownRejectGuestState = 1U << 11,
    HvNativeTeardownRejectCpl = 1U << 12,
    HvNativeTeardownRejectParameters = 1U << 13,
    HvNativeTeardownRejectVmcsRead = 1U << 14,
    HvNativeTeardownRejectDescriptorContract = 1U << 15,
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
// These two slots live in the existing tail padding before the host DR7 slot.
// They are teardown metadata, not architectural guest state, so keep them out
// of GuestContext to avoid increasing its 64-byte-aligned sizeof.
constexpr u64 VMEXIT_NATIVE_IDT_BASE_OFFSET = 0x1140;
constexpr u64 VMEXIT_NATIVE_IDT_LIMIT_OFFSET = 0x1148;
static_assert(offsetof(GuestContext, GuestDebugctl) + sizeof(u64) <=
                  VMEXIT_NATIVE_IDT_BASE_OFFSET,
              "native IDT base overlaps GuestContext fields");
static_assert(VMEXIT_NATIVE_IDT_LIMIT_OFFSET + sizeof(u64) <=
                  VMEXIT_HOST_DR7_OFFSET,
              "native IDT metadata overlaps host DR7 slot");
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

    // VMX-root uses a private IDT copied from the owning CPU's Windows IDT.
    // Critical exception gates point at tiny assembly stubs that publish raw
    // fault evidence before the normal kernel bugcheck path is attempted.
    void* VmxHostIdt;
    u64   VmxHostIdtBase;

    // Fixed-size nonpaged storage owned by this logical processor. The write
    // index is monotonically increasing so readers can recover the newest
    // records without taking a lock at bugcheck time
    HvTraceRecord* TraceRing;
    u32   TraceCapacity;
    volatile __int64 TraceWriteIndex;

    // Per-CPU host state and VMX revision.  These values must be obtained on
    // the logical processor that executes VMXON; VMX capability MSRs are not
    // required to be identical across heterogeneous Intel packages.
    u64   HostCr3;
    // capture raw and normalized CR3 values at the VMCS boundary so a
    // late-launch failure can distinguish KPTI or PCID state from a bad VMCS
    // write without relying on debugger output from a DPC
    u64   LaunchRawGuestCr3;
    u64   LaunchGuestCr3;
    u64   LaunchRawHostCr3;
    u64   LaunchHostCr3;
    u64   LaunchCr3Metadata;
    u64   OriginalCr0;
    u64   OriginalCr4;
    u64   VmxBasic;
    u32   RevisionId;
    // Capability profile selected for this logical processor.  The assembly
    // save contract is global, while optional VMX controls are local so
    // heterogeneous P/E cores can choose their own safe control set.
    u32   VmxProfile;
    // CPUID identity captured on the processor that owns VMXON. These fields
    // are diagnostic and also select the generation-specific control branch.
    u32   CpuFamily;
    u32   CpuModel;
    u32   CpuStepping;
    u32   CpuCoreType;
    u32   CpuBranch;
    volatile long VmcsWriteFailed;
    // 0 means no writer, 1 means diagnostics are being published, and 2
    // means the first failing VMWRITE record is complete
    volatile long VmcsWriteState;
    volatile long VmcsReadFailed;
    volatile long VmcsSetupPhase;
    // publish the failure reason only after both argument slots are complete
    volatile long VmcsFailureCommitState;
    volatile long VmcsFailureReason;
    u64   VmcsFailureArg0;
    u64   VmcsFailureArg1;
    u64   FirstVmcsWriteField;
    u64   FirstVmcsWriteFlags;
    u64   FirstVmcsWriteError;
    u64   FirstVmcsReadField;
    u64   FirstVmcsReadFlags;
    u64   LastVmclearFlags;
    u64   LastVmptrldFlags;
    volatile long VmcsCurrent;
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

    // stopped is published only after the unload callback has returned
    // from the non-returning VMXOFF and IRET transition
    volatile long TeardownQuiesced;

    // only the authenticated stop rendezvous may authorize the native
    // teardown marker in the assembly return path
    volatile long TeardownRequest;

    // State is published with InterlockedExchange so lifecycle callbacks can
    // inspect it without taking a lock at IPI_LEVEL.
    volatile long State;

    // XCR0 is not part of VMCS guest/host state. The guest mask may be a
    // validated subset of the host mask; the assembly path switches to the
    // host mask while C++ runs and restores this value before VMRESUME.
    u64   HostXcr0;

    // Diagnostic counters are kept per logical processor so the VM-exit path
    // can report the first failures without flooding the kernel debugger.
    volatile long VmExitCount;

    // The staged launch DPC arms this token immediately before a private
    // CPUID.  The VM-exit handler publishes one immutable result, and the
    // DPC only reports success after the CPUID instruction has returned.
    volatile long FirstExitProbeState;
    volatile long FirstExitProbeBaselineVmExits;
    volatile long FirstExitProbeBaselineVmResumes;
    volatile long FirstExitProbeObservedVmExits;
    volatile long FirstExitProbeObservedVmResumes;
    volatile long FirstExitProbeReason;
    volatile long FirstExitProbeAction;
    volatile u64 FirstExitProbeResumeFlags;

    // These fields are a passive-level diagnostic snapshot.  They are written
    // by the owning processor and read only after an IPI rendezvous completes.
    volatile long LaunchStage;
    // This checkpoint identifies the last local contract block reached before
    // a launch failure. It is separate from the lifecycle stage used by stop.
    volatile long LaunchCheckStage;
    volatile long LastExitReason;
    volatile u32 LastExitReasonRaw;
    volatile u32 LastExitReasonBasic;
    volatile u32 LastExitEntryFailure;
    // For RDMSR and WRMSR exits this is the guest ECX value. Keep it beside
    // the raw reason so a transport loss still identifies the intercepted MSR.
    volatile u32 LastExitMsrIndex;
    u32 LastExitMsrReserved;
    u64 LastExitMsrValue;
    volatile u64 LastLaunchFlags;
    volatile u64 LastVmResumeFlags;
    volatile u64 LastVmInstructionRflags;
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
    u64 LastGuestCr2;
    u64 LastGuestCs;
    u64 LastGuestSs;
    u64 LastGuestTr;
    u32 LastGuestCsAr;
    u32 LastGuestSsAr;
    u32 LastGuestTrAr;
    u32 LastGuestInterruptibility;
    u32 LastGuestActivity;
    // VM-entry and VM-exit interruption fields are captured before the exit
    // handler clears the one-shot VM-entry request
    u32 LastVmEntryIntrInfo;
    u32 LastVmEntryIntrError;
    u32 LastVmEntryInstructionLength;
    u32 LastVmExitIntrInfo;
    u32 LastVmExitIntrError;
    u32 LastIdtVectoringInfo;
    u32 LastIdtVectoringError;
    u32 LastGuestPendingDbgExceptions;
    volatile long LastEventSnapshotValid;
    u64 LastGuestDr7;
    u64 LastGuestDebugctl;
    u64 LastPtCtl;
    u64 LastGuestEfer;
    u64 LastGuestPat;
    u64 LastGuestXcr0;
    u64 LastGuestXss;
    u64 LastGuestSCet;
    u64 LastGuestSsp;
    u64 LastGuestInterruptSspTable;
    u64 LastVmInstructionError;
    // a validity mask accompanies the diagnostic values because VM-entry
    // failure leaves most VM-exit information fields unmodified
    volatile u64 VmcsDiagnosticValidity;

    // The first fatal VMCS image is immutable after Committed is published.
    // Interlocked operations provide the release/acquire boundary; root paths
    // must not depend on allocation, locks, formatting, or debugger output.
    volatile long FatalSnapshotCommitState;
    volatile long NativeTeardownRejectMask;

    // vmcs readback mismatches are distinct from failed VMREAD instructions
    // keep a first-wins record so a bad field encoding or width conversion is
    // rejected before VMLAUNCH and remains diagnosable after the callback
    // returns to passive level
    volatile long VmcsReadState;
    u64   FirstVmcsReadError;
    volatile long VmcsValueMismatch;
    volatile long VmcsMismatchState;
    u64   FirstVmcsMismatchField;
    u64   FirstVmcsMismatchExpected;
    u64   FirstVmcsMismatchActual;
    u64   FirstVmcsMismatchMask;
};

static_assert((offsetof(VcpuContext, FatalSnapshotCommitState) % alignof(long)) == 0,
              "fatal snapshot commit state must be naturally aligned");
static_assert((offsetof(VcpuContext, NativeTeardownRejectMask) % alignof(long)) == 0,
              "native teardown reject mask must be naturally aligned");
static_assert((offsetof(VcpuContext, FirstExitProbeState) % alignof(long)) == 0,
              "first exit probe state must be naturally aligned");
static_assert((offsetof(VcpuContext, FirstExitProbeResumeFlags) % alignof(u64)) == 0,
              "first exit probe flags must be naturally aligned");
static_assert((offsetof(VcpuContext, VmcsReadState) % alignof(long)) == 0,
              "vmcs read state must be naturally aligned");
static_assert((offsetof(VcpuContext, VmcsMismatchState) % alignof(long)) == 0,
              "vmcs mismatch state must be naturally aligned");
static_assert((offsetof(VcpuContext, VmcsFailureCommitState) % alignof(long)) == 0,
              "vmcs failure state must be naturally aligned");
static_assert((offsetof(VcpuContext, VmcsFailureArg0) % alignof(u64)) == 0,
              "vmcs failure argument zero must be naturally aligned");
static_assert((offsetof(VcpuContext, VmcsFailureArg1) % alignof(u64)) == 0,
              "vmcs failure argument one must be naturally aligned");
static_assert((offsetof(VcpuContext, VmcsDiagnosticValidity) % alignof(u64)) == 0,
              "vmcs diagnostic validity must be naturally aligned");
