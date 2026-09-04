//
// Created by cwuom on 17 Feb 2026.
//

// ==============================================================================
// vmm.cpp
// Hypervisor Implementation
// ==============================================================================

#include "header/common.h"
#include <intrin.h>
#include <ntifs.h>
#include <ntdef.h>

#include "header/vmm.h"
#include "header/vmx.h"
#include "header/vmx_contract.h"

extern "C" void StopHypervisor();
extern "C" PDRIVER_OBJECT g_HvDriverObject;

#ifndef NESTED_HV_BUILD_ID
#define NESTED_HV_BUILD_ID 0
#endif
static constexpr u64 kHvBuildId = static_cast<u64>(NESTED_HV_BUILD_ID);
// "HVMX" keeps driver-originated fatal dumps distinct from Windows bugchecks
static constexpr ULONG kHvFatalBugCheck = 0x48564D58UL;

// ==============================================================================
// External Assembly Linking
// ==============================================================================
extern "C" {
    // defined in arch.asm
    u64 HvVmxOn(u64* Phys);
    void HvVmxOff();
    u64 HvVmClear(u64* Phys);
    u64 HvVmPtrSt(u64* Phys);
    u64 HvVmPtrLd(u64* Phys);
    u64 HvVmWrite(u64 Field, u64 Value);
    u64 HvVmReadChecked(u64 Field, u64* Value);

    u64 HvLaunchGuest();
    void HvRestoreStateAndReturn(GuestContext* Ctx);
    void GuestStartThunk();
    void HvCall(u64 Magic, u64 Command, u64 Arg1, u64 Arg2);

    // entry point for vm-exit, used in vmcs setup
    void HvVmExitEntryPoint();

    // VMX-root exception stubs. The private host IDT keeps Windows' original
    // descriptor attributes and replaces only these synchronous fault targets.
    void HvHostException0();
    void HvHostNmi2();
    void HvHostException5();
    void HvHostException6();
    void HvHostException7();
    void HvHostException8();
    void HvHostException10();
    void HvHostException11();
    void HvHostException12();
    void HvHostException13();
    void HvHostException14();
    void HvHostException16();
    void HvHostException17();
    void HvHostException18();
    void HvHostException19();
    void HvHostException21();

    void HvTraceCurrentVcpuEvent(u32 Event);
    bool HvFaultInjectedCurrent(u32 Stage);
    void HvCaptureFatalSnapshotPreVmxoff(GuestContext* Ctx);

    // register helpers
    u16 GetCs(); u16 GetDs(); u16 GetEs(); u16 GetSs(); u16 GetFs(); u16 GetGs();
    u16 GetTr(); u16 GetLdtr();
    u64 GetGdtBase(); u16 GetGdtLimit(); u64 GetIdtBase(); u16 GetIdtLimit();
    u64 GetRflags();
    u64 GetDr7();
    u32 HvGetSegmentLimit(u16 Selector);
    u32 HvGetSegmentAr(u16 Selector);

    // fixed-frame IPI launch wrapper in arch.asm and its C++ preparation
    // helpers.  VMLAUNCH never returns through compiler-generated state on a
    // successful entry; the wrapper owns that continuation explicitly.
    ULONG_PTR EnableHvCallback(ULONG_PTR Context);
    ULONG PrepareHvCallback(ULONG_PTR Context, void* GuestSp, void* GuestIp);
    void AbortHvLaunch(u64 Rflags);
    bool HvClearCurrentVmcsAndRecord();
    __declspec(noreturn) void HvFailVmcsClear();
    bool MarkCurrentVcpuLaunched();
    void MarkCurrentVcpuRunning();
    void MarkCurrentVcpuParked();
    bool MarkCurrentVcpuTearingDown();
    void MarkCurrentVcpuStopped();
    ULONG HandleVmResumeFailure(GuestContext* Ctx, u64 ResumeFlags);
    __declspec(noreturn) void HvFatalBugCheck(GuestContext* Ctx);
    extern volatile LONG g_HvLaunchTelemetrySignature;
    extern volatile LONG g_HvLaunchExpectedProcessors;
    extern volatile LONG g_HvLaunchProbeEntered;
    extern volatile LONG g_HvLaunchProbeCompleted;
    extern volatile LONG g_HvLaunchDispatchEntered;
    extern volatile LONG g_HvLaunchAssemblyEntered;
    extern volatile LONG g_HvLaunchPrepareEntered;
    extern volatile LONG g_HvLaunchPrepareSucceeded;
    extern volatile LONG g_HvLaunchGuestEntered;
    extern volatile LONG g_HvLaunchVmlaunchIssued;
    extern volatile LONG g_HvLaunchVmlaunchReturned;
    extern volatile LONG g_HvLaunchGuestStarted;
    extern volatile LONG g_HvLaunchMarkedLaunched;
    extern volatile LONG g_HvLaunchVmExitAsmReached;
    extern volatile LONG g_HvLaunchFirstVmExitEntered;
    extern volatile LONG g_HvLaunchDispatchReturned;
    extern volatile LONG g_HvLaunchLastProbeProcessor;
    extern volatile LONG g_HvLaunchLastDispatchProcessor;
    extern volatile LONG g_HvLaunchLastPrepareProcessor;
    extern volatile LONG g_HvLaunchLastReturnProcessor;
}

// ==============================================================================
// Global State
// ==============================================================================
VcpuContext* g_VcpuData = nullptr;
u32 g_ProcessorCount = 0;
extern "C" {
__declspec(align(64)) HvHostFaultRecord g_HvHostFaultRecord = {};
__declspec(align(64)) volatile LONG64 g_HvRootNmiCount = 0;
}
static volatile LONG g_HvLifecycle = 0;
static volatile LONG g_HvImagePinned = 0;
static constexpr LONG kHvLifecycleIdle = 0;
static constexpr LONG kHvLifecycleStarting = 1;
static constexpr LONG kHvLifecycleRunning = 2;
static constexpr LONG kHvLifecycleStopping = 3;
static constexpr LONG kHvLifecycleQuarantined = 4;

enum TargetOperation : LONG {
    TargetOperationNone = 0,
    TargetOperationProbe = 1,
    TargetOperationLaunch = 2,
    TargetOperationStop = 3,
    TargetOperationRuntimeCanary = 4,
};

enum TargetWorkState : LONG {
    TargetWorkIdle = 0,
    TargetWorkQueued = 1,
    TargetWorkEntered = 2,
    TargetWorkExecuting = 3,
    TargetWorkSucceeded = 4,
    TargetWorkFailed = 5,
    TargetWorkCancelled = 6,
};

struct __declspec(align(64)) TargetCpuWork {
    PROCESSOR_NUMBER Target;
    u32 ProcessorIndex;
    volatile LONG Generation;
    volatile LONG Operation;
    volatile LONG State;
    volatile LONG TimedOut;
    volatile LONG ObservedProcessorTag;
    NTSTATUS Result;
    HANDLE ThreadHandle;
    u64 QueueTime;
    u64 EnterTime;
    u64 ReturnTime;

    // post-DPC canary evidence. The worker runs after the launch DPC has
    // returned and therefore exercises ordinary scheduler context on the
    // virtualized processor rather than the launch callback's saved frame.
    volatile LONG CanaryBaselineVmExits;
    volatile LONG CanaryObservedVmExits;
    volatile LONG CanaryBaselineVmResumes;
    volatile LONG CanaryObservedVmResumes;
    volatile LONG CanaryLastExitReason;
    volatile LONG CanaryIrql;
    u32 CanaryCpuidEax;
    u32 CanaryCpuidEbx;
    u32 CanaryCpuidEcx;
    u32 CanaryCpuidEdx;
    u64 CanaryCr3;
    u64 CanaryCr4;
};

// a launch DPC runs on the target processor's existing kernel context. Keep
// its bookkeeping in nonpaged storage so a timeout can quarantine the image
// without leaving a callback pointing at a caller stack frame
struct TargetLaunchDpcWork {
    KDPC Dpc;
    KEVENT Done;
    PROCESSOR_NUMBER Target;
    u32 ProcessorIndex;
    volatile LONG Generation;
    volatile LONG State;
    volatile LONG TimedOut;
    volatile LONG DpcQueued;
    volatile LONG DpcCompleted;
    volatile LONG ObservedProcessorTag;
    volatile LONG ObservedIrql;
    NTSTATUS Result;
    u64 QueueTime;
    u64 EnterTime;
    u64 ReturnTime;
};

static TargetCpuWork* g_HvTargetCpuWork = nullptr;
static TargetLaunchDpcWork* g_HvTargetLaunchDpcWork = nullptr;
static volatile LONG g_HvTargetWorkGeneration = 0;
static volatile LONG g_HvTargetActiveProcessor = -1;
// Native CPU0 watchdog. It never executes on the virtualized CPU and only
// observes nonpaged per-CPU state plus the architectural VMX-abort indicator
// at VMCS region byte offset 4. This keeps the diagnostic path outside the
// failing VMX-root context.
static HANDLE g_HvRuntimeWatchdogThread = nullptr;
static volatile LONG g_HvRuntimeWatchdogStop = 0;
static volatile LONG g_HvRuntimeWatchdogTicks = 0;
static volatile LONG g_HvRuntimeWatchdogBreakFired = 0;
static volatile LONG g_HvWaitpkgVmcsEnabled = 0;
static constexpr LONGLONG kRuntimeWatchdogPoll100ns = 100000LL; // 10 ms
static constexpr LONG kRuntimeWatchdogPrintEveryTicks = 50;     // 500 ms
static constexpr u64 kTargetOperationTimeout100ns = 50000000ULL;
static constexpr LONGLONG kTargetCancelGrace100ns = 10000000LL;
static u64 g_VmxBasic = 0;
// VMX host CR3 must always reference the kernel/system address space.  A
// A future caller may invoke the launch path from an arbitrary process, so the
// VMX host CR3 is captured from the system process explicitly
static u64 g_HostCr3 = 0;
static bool g_VmxRequires32BitPhysicalAddress = false;
extern "C" volatile u8 g_LinearAddressBits = 48;

// These flags are populated by InitializeVmxFeatureContract() before any
// processor enters VMX.  They are intentionally global and immutable for the
// lifetime of a hypervisor run: VMCS controls and the assembly save format
// must not change after VMLAUNCH.
static bool g_VmxFeatureContractInitialized = false;
static bool g_VmxFeatureContractValid = false;
extern "C" volatile u8 g_CetVmcsEnabled = 0;
extern "C" volatile u8 g_XsavesEnabled = 0;
extern "C" volatile u8 g_XstateMode = XstateSaveFxsave;
// XSAVES/XRSTORS use this immutable compacted-mask contract. The guest's
// IA32_XSS value is kept separately, so a guest WRMSR never changes the frame
// layout used by the VM-exit assembly.
extern "C" volatile u64 g_XsavesMask = 0;
static u64 g_EnumeratedXssMask = 0;
static u64 g_SupportedXssMask = 0;
// Windows may retain the host IPT selector after this late launch. Accept the
// passive selector for compatibility, but never advertise or execute guest PT.
static u64 g_GuestXssWriteMask = 0;
static u64 g_HostXssMask = 0;
static u64 g_HostXcr0Mask = 0;
static u64 g_DebugctlMask = IA32_DEBUGCTL_ARCHITECTURAL_MASK;
static u32 g_XsaveStateSize = 0;

// VMX control and state-save capabilities vary across Intel generations. The
// assembly path uses one immutable state-save contract, while optional VMX
// instruction controls can be selected per processor. Guest-visible optional
// instructions are reduced to the intersection of all participating CPUs so a
// thread migration cannot change the CPUID contract.
enum VmxCapabilityProfile : u32 {
    VmxProfileLegacyControls = 1U << 0,
    VmxProfileTrueControls = 1U << 1,
    VmxProfileSecondaryControls = 1U << 2,
    VmxProfileXsaves = 1U << 3,
    VmxProfileCetVmcs = 1U << 4,
    VmxProfileRdtscp = 1U << 5,
    VmxProfileInvpcid = 1U << 6,
    VmxProfileTertiaryControls = 1U << 7,
};
static u32 g_VmxCapabilityProfile = 0;
// Guest CPUID must not expose optional instructions until every launch
// callback has contributed its local capability intersection.  The candidate
// is reduced during the synchronized broadcast; the published value remains
// zero while any processor may still be entering VMX.
static volatile LONG g_VmxGuestOptionalProfile = 0;
static volatile LONG g_VmxGuestOptionalProfileCandidate = 0;
static constexpr u32 kGuestOptionalProfileMask =
    VmxProfileRdtscp | VmxProfileInvpcid;

enum VmxControlGeneration : u32 {
    VmxGenerationLegacy = 0,
    VmxGenerationTrue = 1,
    VmxGenerationTrueSecondary = 2,
    VmxGenerationTrueTertiary = 3,
};

static VmxControlGeneration SelectVmxControlGeneration(u32 profile) {
    if ((profile & VmxProfileTrueControls) == 0) {
        return VmxGenerationLegacy;
    }
    if ((profile & VmxProfileTertiaryControls) != 0) {
        return VmxGenerationTrueTertiary;
    }
    if ((profile & VmxProfileSecondaryControls) != 0) {
        return VmxGenerationTrueSecondary;
    }
    return VmxGenerationTrue;
}
// Detailed messages are emitted only from passive-level code. Root/IPI paths
// use the binary recorder so enabling diagnostics cannot stall all processors.
extern "C" volatile LONG g_HvVerboseLogging = 1;

#define HV_PASSIVE_PRINT(...) \
    do { \
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__); \
        } \
    } while (0)

#define HV_VERBOSE_PRINT(...) \
    do { \
        if (g_HvVerboseLogging != 0) { \
            HV_PASSIVE_PRINT(__VA_ARGS__); \
        } \
    } while (0)
// V47 preserves the CET state selected by the running Windows instance and
// does not redefine its already-established late-launch feature contract.

static constexpr long kExitActionNone = 0;
static constexpr long kExitActionResume = 1;
static constexpr long kExitActionAbort = 2;
static constexpr long kExitActionHalt = 3;
static constexpr long kExitActionInject = 4;

enum FirstExitProbeState : long {
    FirstExitProbeIdle = 0,
    FirstExitProbeArmed = 1,
    FirstExitProbeVmExitEntered = 2,
    FirstExitProbeExitValidated = 3,
    FirstExitProbeReturned = 4,
    FirstExitProbeFailed = 5,
};

static constexpr u32 kFirstExitProbeLeaf =
    static_cast<u32>(HYPERVISOR_MAGIC);
static constexpr u32 kFirstExitProbeEbx = 0xDEADC0DEU;
static constexpr u32 kFirstExitProbeEcx = 0x00C0FFEEU;
static constexpr u32 kFirstExitProbeEdx = 0x48564856U;

// user-mode self-test probe. CPUID is unconditional-exit in VMX non-root,
// so this response is emitted only after the instruction reaches our VM-exit
// handler on the logical processor where the caller is pinned.
static constexpr bool kEnableUserCpuidProbe = true;
static constexpr u32 kUserProbeLeaf = static_cast<u32>(HYPERVISOR_MAGIC);
static constexpr u32 kUserProbeSubleaf = 0x56455249U;
static constexpr u32 kUserProbeSignatureEax = 0x48565031U;
static constexpr u32 kUserProbeSignatureEdx = 0x564D5831U;

// IA32_DEBUGCTL has model-specific extensions. Keep the guest contract to the
// architectural bits until a per-model capability probe is available.
static constexpr u64 kDebugctlArchitecturalMask =
    IA32_DEBUGCTL_ARCHITECTURAL_MASK;
static constexpr u64 kCr0WriteProtect = 1ULL << 16;

// V54 promotes the V53 contract to all logical processors. Keep the staged
// launch path: each target must return from VMLAUNCH, complete the first-exit
// probe, return from its launch DPC, and pass a scheduler-context CPUID canary
// before the next logical processor is allowed to enter VMX. CPU0 stays native
// until every other processor is verified, then it is launched last.
static constexpr bool kDebugSingleCpu = false;
static constexpr u32  kDebugCpuIndex = 8; // retained for single-CPU diagnostics

// Keep the startup coordinator native during the staged pass. Unlike V44, this
// does not permanently exclude CPU0 from VMX; full-core mode migrates the
// startup thread to a verified VMX CPU and launches the coordinator last.
static constexpr bool kReserveCoordinatorCpu = true;
static constexpr u32  kCoordinatorCpuIndex = 0;

// keep the vmx host stack inside its allocation, matching HyperDbg's
// last-byte-then-align convention
static constexpr SIZE_T kVmxHostStackSize = 0x8000;
static constexpr u64 kVmxHostStackAlignment = 0x40;

// hyperdbg uses one KeGenericCallDpc rendezvous, but that path cannot time out
// when a processor never returns from VM-entry or the first VM-exit
// keep it available for controlled comparison and use target DPCs by default
// so one processor cannot hide the other results
static constexpr bool kUseHyperDbgGenericLaunch = false;

// validate one CPUID exit and VMRESUME before the coordinator launches the
// next processor. This keeps a broken first-exit path from being propagated
// to every logical processor during late-launch bring-up.
static constexpr bool kEnableLaunchFirstExitProbe = true;

static __forceinline bool ShouldLaunchOnThisProcessor(u32 id) {
    return kDebugSingleCpu ? id == kDebugCpuIndex : true;
}

static __forceinline bool ShouldReportLaunchResult(u32 processorIndex) {
    return ShouldLaunchOnThisProcessor(processorIndex);
}

static __forceinline u32 ExpectedLaunchProcessorCount() {
    if (kDebugSingleCpu) return 1U;
    return g_ProcessorCount;
}

static __forceinline u32 CurrentProcessorIndex();
static __forceinline u32 ControlMsr(u64 vmxBasic, u32 legacyMsr, u32 trueMsr);
static __forceinline bool IsCanonical(u64 value);
static bool ReadMsrSafe(u32 msr, u64* value);
static u64 GetDebugctlCapabilityMask();
static bool UpdateNativeTeardownContract(VcpuContext* vcpu);

enum HvFaultStage : u32 {
    HvFaultBeforeVmxon = 1,
    HvFaultAfterVmxon = 2,
    HvFaultAfterVmclear = 3,
    HvFaultAfterVmptrld = 4,
    HvFaultAfterVmcsControls = 5,
    HvFaultAfterHostState = 6,
    HvFaultAfterGuestState = 7,
    HvFaultBeforeVmlaunch = 8,
    HvFaultVmlaunchFailure = 9,
    HvFaultLateVmEntry = 10,
    HvFaultFirstVmexit = 11,
    HvFaultBeforeVmresume = 12,
    HvFaultVmresumeFailure = 13,
    HvFaultTeardown = 14,
};

static __forceinline bool ShouldInjectFault(u32 cpu, u32 stage) {
#if defined(HV_TEST_FAIL_CPU) && defined(HV_TEST_FAIL_STAGE)
    return static_cast<u32>(HV_TEST_FAIL_CPU) == cpu &&
           static_cast<u32>(HV_TEST_FAIL_STAGE) == stage;
#else
    UNREFERENCED_PARAMETER(cpu);
    UNREFERENCED_PARAMETER(stage);
    return false;
#endif
}

static __forceinline void WriteHvTrace(VcpuContext* vcpu, u32 cpu,
                                       HvTraceEvent event, u64 arg0 = 0,
                                       u64 arg1 = 0, u64 arg2 = 0,
                                       u64 arg3 = 0) {
    if (!vcpu || !vcpu->TraceRing || vcpu->TraceCapacity == 0) return;
    const u64 sequence = static_cast<u64>(
        InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(
                                    &vcpu->TraceWriteIndex)) - 1);
    const u32 slot = static_cast<u32>(sequence % vcpu->TraceCapacity);
    HvTraceRecord* record = &vcpu->TraceRing[slot];
    record->Tsc = __rdtsc();
    record->Cpu = cpu;
    record->Lifecycle = static_cast<u16>(
        InterlockedCompareExchange(&g_HvLifecycle, 0, 0));
    record->Stage = static_cast<u16>(
        InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0));
    record->Event = static_cast<u32>(event);
    record->Arg0 = arg0;
    record->Arg1 = arg1;
    record->Arg2 = arg2;
    record->Arg3 = arg3;
    MemoryBarrier();
    record->Sequence = sequence;
}

extern "C" void HvTraceCurrentVcpuEvent(u32 event) {
    if (!g_VcpuData) return;
    const u32 cpu = CurrentProcessorIndex();
    if (cpu < g_ProcessorCount) {
        WriteHvTrace(&g_VcpuData[cpu], cpu,
                     static_cast<HvTraceEvent>(event));
    }
}

extern "C" bool HvFaultInjectedCurrent(u32 stage) {
    return ShouldInjectFault(CurrentProcessorIndex(), stage);
}

// VMX capability MSRs expose mandatory-one bits in the low half and optional
// allowed-one bits in the high half. Either half can make a requested one
// architecturally valid.
static __forceinline bool ControlBitCanBeOne(u64 capability, u32 mask) {
    const u32 mandatoryOne = static_cast<u32>(capability);
    const u32 allowedOne = static_cast<u32>(capability >> 32);
    return ((mandatoryOne | allowedOne) & mask) == mask;
}

static u32 BuildVmxCapabilityProfile(u64 vmxBasic, bool xsaves,
                                     bool cetVmcs) {
    u32 profile = (vmxBasic & VMX_BASIC_TRUE_CONTROLS) != 0
                      ? VmxProfileTrueControls
                      : VmxProfileLegacyControls;
    const u32 primaryMsr = ControlMsr(vmxBasic,
                                      MSR_IA32_VMX_PROCBASED_CTLS,
                                      MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    u64 primaryControls = 0;
    const bool primaryRead = ReadMsrSafe(primaryMsr, &primaryControls);
    u64 secondaryControls = 0;
    const bool secondaryField =
        primaryRead &&
        ControlBitCanBeOne(primaryControls,
                           CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
        ReadMsrSafe(MSR_IA32_VMX_PROCBASED_CTLS2, &secondaryControls);
    if (secondaryField) {
        profile |= VmxProfileSecondaryControls;
    }
    if (xsaves && secondaryField &&
        ControlBitCanBeOne(secondaryControls, SECONDARY_ENABLE_XSAVES)) {
        profile |= VmxProfileXsaves;
    }
    if (cetVmcs) profile |= VmxProfileCetVmcs;
    int regs[4] = {};
    __cpuid(regs, 0);
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);
    if (maxBasicLeaf >= 7) {
        __cpuidex(regs, 7, 0);
        if (secondaryField &&
            (regs[1] & (1 << 10)) != 0 &&
            ControlBitCanBeOne(secondaryControls, SECONDARY_ENABLE_INVPCID)) {
            profile |= VmxProfileInvpcid;
        }
    }
    __cpuidex(regs, 0x80000000, 0);
    const u32 maxExtendedLeaf = static_cast<u32>(regs[0]);
    if (maxExtendedLeaf >= 0x80000001) {
        __cpuidex(regs, 0x80000001, 0);
        if (secondaryField &&
            (regs[3] & (1 << 27)) != 0 &&
            ControlBitCanBeOne(secondaryControls, SECONDARY_ENABLE_RDTSCP)) {
            profile |= VmxProfileRdtscp;
        }
    }

    if (primaryRead &&
        ControlBitCanBeOne(primaryControls,
                           CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)) {
        u64 tertiaryControls = 0;
        if (ReadMsrSafe(MSR_IA32_VMX_PROCBASED_CTLS3, &tertiaryControls)) {
            profile |= VmxProfileTertiaryControls;
        }
    }
    return profile;
}

struct IntelCpuIdentity {
    u32 Family;
    u32 Model;
    u32 Stepping;
    u32 CoreType;
    IntelCpuBranch Branch;
    bool GenuineIntel;
};

static IntelCpuBranch SelectIntelCpuBranch(u32 family, u32 model,
                                           u32 coreType, u32 profile) {
    // Keep the hybrid path allow-listed.  A future core type can share the
    // CPUID encoding while changing VMX capability details; fail closed until
    // that model has been audited instead of guessing from the core type.
    const bool knownHybridModel =
        family == 6U &&
        (model == 0x97U || model == 0x9AU || model == 0xB7U ||
         model == 0xBAU || model == 0xBFU);
    // Intel hybrid processors identify a performance core as 40h and an
    // efficient core as 20h in CPUID.1A. Keep those paths separate because
    // their VMX capability MSRs are sampled on the executing logical CPU.
    if (coreType == 0x40U) {
        return knownHybridModel ? IntelCpuBranchHybridPerformance
                                : IntelCpuBranchHybridUnknown;
    }
    if (coreType == 0x20U) {
        return knownHybridModel ? IntelCpuBranchHybridEfficient
                                : IntelCpuBranchHybridUnknown;
    }
    if (coreType != 0) return IntelCpuBranchHybridUnknown;

    // Family 6 model 0x97 is Alder Lake and 0xB7 is Raptor Lake.  The 14th
    // generation desktop parts use the same true-control VMX contract, but the
    // model test stays explicit so an unknown future model cannot silently use
    // a modern branch without a capability bit proving it safe.
    const bool knownModernModel = knownHybridModel;
    if (family != 6U) return IntelCpuBranchUnknown;
    if (knownModernModel &&
        (profile & VmxProfileTrueControls) != 0) {
        return IntelCpuBranchModern;
    }
    // Older family-6 parts use the legacy branch even when firmware exposes
    // true-control MSRs. Their optional controls are still selected from the
    // local capability profile, so this branch is not a guessed model table.
    return IntelCpuBranchLegacy;
}

static IntelCpuIdentity QueryIntelCpuIdentity(u32 profile) {
    IntelCpuIdentity identity{};
    identity.Branch = IntelCpuBranchUnknown;

    int regs[4] = {};
    __cpuid(regs, 0);
    identity.GenuineIntel =
        static_cast<u32>(regs[1]) == 0x756E6547U &&
        static_cast<u32>(regs[3]) == 0x49656E69U &&
        static_cast<u32>(regs[2]) == 0x6C65746EU;
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);
    if (!identity.GenuineIntel || maxBasicLeaf < 1U) return identity;

    __cpuidex(regs, 1, 0);
    const u32 version = static_cast<u32>(regs[0]);
    const u32 baseFamily = (version >> 8) & 0xFU;
    const u32 baseModel = (version >> 4) & 0xFU;
    const u32 extendedFamily = (version >> 20) & 0xFFU;
    const u32 extendedModel = (version >> 16) & 0xFU;
    identity.Family = baseFamily == 0xFU
                          ? baseFamily + extendedFamily
                          : baseFamily;
    identity.Model = (baseFamily == 0x6U || baseFamily == 0xFU)
                         ? baseModel | (extendedModel << 4)
                         : baseModel;
    identity.Stepping = version & 0xFU;

    if (maxBasicLeaf >= 0x1AU) {
        __cpuidex(regs, 0x1A, 0);
        identity.CoreType = (static_cast<u32>(regs[0]) >> 24) & 0xFFU;
    }
    identity.Branch = SelectIntelCpuBranch(identity.Family, identity.Model,
                                           identity.CoreType, profile);
    return identity;
}

static const char* IntelCpuBranchName(IntelCpuBranch branch) {
    switch (branch) {
        case IntelCpuBranchLegacy: return "legacy";
        case IntelCpuBranchModern: return "modern";
        case IntelCpuBranchHybridPerformance: return "hybrid-p";
        case IntelCpuBranchHybridEfficient: return "hybrid-e";
        case IntelCpuBranchHybridUnknown: return "hybrid-unknown";
        default: return "unknown";
    }
}

static bool IsIntelCpuBranchCompatible(const IntelCpuIdentity& identity,
                                       u32 profile) {
    if (!identity.GenuineIntel || identity.Branch == IntelCpuBranchUnknown ||
        identity.Branch == IntelCpuBranchHybridUnknown) {
        return false;
    }

    const bool trueControls = (profile & VmxProfileTrueControls) != 0;
    const bool secondaryControls =
        (profile & VmxProfileSecondaryControls) != 0;
    switch (identity.Branch) {
        case IntelCpuBranchHybridPerformance:
        case IntelCpuBranchHybridEfficient:
            // The hybrid branches use the same architectural VMX fields, but
            // require the true/secondary capability path independently on each
            // P/E core before a VMCS is constructed.
            return trueControls && secondaryControls;
        case IntelCpuBranchModern:
            return trueControls;
        case IntelCpuBranchLegacy:
            return true;
        default:
            return false;
    }
}

// CPUID.0D.1:EBX describes only the state selected by the current XCR0 and
// IA32_XSS values.  The VM-exit frame instead uses one immutable XSAVES mask,
// so calculate the compacted size from every component in that mask.
static bool ComputeXsaveAreaSize(u64 xcr0Mask, u64 xssMask,
                                 u64* enumeratedXss, u32* areaSize) {
    if (!enumeratedXss || !areaSize) return false;

    int regs[4] = {};
    __cpuid(regs, 0);
    if (static_cast<u32>(regs[0]) < 0xD) return false;

    __cpuidex(regs, 0xD, 0);
    const u64 supportedXcr0 = static_cast<u32>(regs[0]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    if ((xcr0Mask & ~supportedXcr0) != 0 ||
        (xcr0Mask & 0x3ULL) != 0x3ULL) {
        return false;
    }

    __cpuidex(regs, 0xD, 1);
    const u64 xssCapabilities =
        (static_cast<u32>(regs[2]) |
         (static_cast<u64>(static_cast<u32>(regs[3])) << 32)) &
        ~(1ULL << 63);
    *enumeratedXss = xssCapabilities;
    if ((xssMask & ~xssCapabilities) != 0) return false;

    u64 offset = 576;
    const u64 compactedMask = xcr0Mask | xssMask;
    for (u32 component = 2; component < 64; ++component) {
        const u64 bit = 1ULL << component;
        if ((compactedMask & bit) == 0) continue;

        __cpuidex(regs, 0xD, static_cast<int>(component));
        const u32 componentSize = static_cast<u32>(regs[0]);
        if (componentSize == 0) return false;
        const u32 componentFlags = static_cast<u32>(regs[2]);
        const bool xssComponent = (componentFlags & 0x1U) != 0;
        const bool xcr0Component = !xssComponent;
        if (((xcr0Mask & bit) != 0 && !xcr0Component) ||
            ((xssMask & bit) != 0 && !xssComponent)) {
            return false;
        }
        // Intel's compacted XSAVE format aligns selected components when
        // CPUID.(D,n).ECX[1] requests the next 64-byte boundary
        if ((componentFlags & 0x2U) != 0) {
            offset = (offset + 63ULL) & ~63ULL;
        }
        offset += componentSize;
        if (offset > MAXULONG) return false;
    }

    *areaSize = static_cast<u32>(offset);
    return true;
}

    // cpuid.0d.0 reports the standard, non-compacted XSAVE layout. Keep this
    // separate from ComputeXsaveAreaSize because its EBX offsets are not valid
    // for the compacted XSAVES format used by the VM-exit frame
static bool ComputeStandardXsaveAreaSize(u64 xcr0Mask, u32* areaSize) {
    if (!areaSize) return false;

    int regs[4] = {};
    __cpuid(regs, 0);
    if (static_cast<u32>(regs[0]) < 0xD) return false;

    __cpuidex(regs, 0xD, 0);
    const u64 supportedXcr0 = static_cast<u32>(regs[0]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    if ((xcr0Mask & ~supportedXcr0) != 0 ||
        (xcr0Mask & 0x3ULL) != 0x3ULL) {
        return false;
    }

    u64 size = 576;
    for (u32 component = 2; component < 64; ++component) {
        const u64 bit = 1ULL << component;
        if ((xcr0Mask & bit) == 0) continue;

        __cpuidex(regs, 0xD, static_cast<int>(component));
        const u32 componentSize = static_cast<u32>(regs[0]);
        const u32 componentOffset = static_cast<u32>(regs[1]);
        if (componentSize == 0 || componentOffset < 576) return false;

        const u64 end = static_cast<u64>(componentOffset) + componentSize;
        if (end > MAXULONG) return false;
        if (end > size) size = end;
    }

    *areaSize = static_cast<u32>(size);
    return true;
}

static bool VmxControlAllows(u32 msr, u32 mask) {
    ULARGE_INTEGER value{};
    __try {
        value.QuadPart = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return ControlBitCanBeOne(value.QuadPart, mask);
}

static bool ReadMsrSafe(u32 msr, u64* value) {
    if (!value) return false;
    __try {
        *value = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static bool WriteMsrSafe(u32 msr, u64 value) {
    __try {
        __writemsr(msr, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static bool EnsureFeatureControlForVmx() {
    u64 featureControl = 0;
    if (!ReadMsrSafe(MSR_IA32_FEATURE_CONTROL, &featureControl)) return false;
    const u64 required = IA32_FEATURE_CONTROL_LOCK |
                         IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX;
    // This MSR is package firmware policy and the lock bit is irreversible
    // until reset. A late-launch driver must never claim it on behalf of the
    // platform; an unlocked or incomplete policy is rejected before VMXON.
    return (featureControl & required) == required;
}

static __forceinline bool IsIntelPtMsr(u32 msr) {
    // pt has reserved holes, so keep the complete architectural window together
    return msr >= MSR_IA32_RTIT_OUTPUT_BASE && msr <= 0x58FU;
}

static __forceinline bool IsCetStateMsr(u32 msr) {
    return msr == MSR_IA32_U_CET || msr == MSR_IA32_S_CET ||
           msr == MSR_IA32_PL0_SSP || msr == MSR_IA32_PL1_SSP ||
           msr == MSR_IA32_PL2_SSP || msr == MSR_IA32_PL3_SSP ||
           msr == MSR_IA32_INTERRUPT_SSP_TABLE;
}

bool IsCETVmcsEnabled() {
    return g_CetVmcsEnabled;
}

bool IsXsavesEnabled() {
    return g_XsavesEnabled;
}

u32 GetXsaveStateSize() {
    return g_XsaveStateSize;
}

static bool IsGdtSelectorUsable(u64 gdtBase, u16 gdtLimit, u16 selector,
                                bool allowNull, bool requireSystem,
                                bool requireCode,
                                bool requireKernelPrivilege,
                                bool requireWritableData) {
    if (selector == 0) return allowNull;
    const u16 offset = selector & 0xFFF8U;
    // segment RPL may be nonzero for the current DS, ES, FS, or GS selector
    // even while the kernel runs at CPL 0. Only LDT selectors lack a GDT base.
    if ((selector & 0x4U) != 0 || offset > gdtLimit ||
        gdtLimit - offset < 7U ||
        !IsCanonical(gdtBase) || !IsCanonical(gdtBase + offset)) {
        return false;
    }
    const auto descriptor = reinterpret_cast<const u8*>(gdtBase + offset);
    const u8 access = descriptor[5];
    const u8 type = access & 0x0FU;
    if ((access & 0x80U) == 0) return false;
    if (requireKernelPrivilege &&
        (((selector & 0x3U) != 0) || (access & 0x60U) != 0)) {
        return false;
    }
    if (requireSystem) {
        return (access & 0x10U) == 0 && (type == 9U || type == 0xBU) &&
               gdtLimit - offset >= 15U;
    }
    if ((access & 0x10U) == 0) return false;

    // Intel VM-entry checks require the accessed bit for every usable
    // CS/SS/DS/ES/FS/GS descriptor. CS must be accessed code; SS must be
    // writable accessed data. DS/ES/FS/GS may legally reference readable
    // accessed code, so executable selectors are not rejected categorically.
    if (requireCode) {
        return (type & 0x9U) == 0x9U;
    }
    if (requireWritableData) {
        return (type & 0x8U) == 0 && (type & 0x3U) == 0x3U;
    }

    // For DS/ES/FS/GS, Intel allows accessed data and readable accessed code.
    // Non-conforming code/data (types 0..11) also requires DPL >= selector RPL.
    const u8 dpl = static_cast<u8>((access >> 5) & 0x3U);
    const u8 rpl = static_cast<u8>(selector & 0x3U);
    if (type <= 0xBU && dpl < rpl) return false;
    if ((type & 0x8U) != 0) {
        return (type & 0xBU) == 0xBU;
    }
    return (type & 0x1U) != 0;
}

static bool IsGuestTrSelectorUsable(u64 gdtBase, u16 gdtLimit,
                                    u16 selector) {
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, selector, false, true, false,
                             true, false)) {
        return false;
    }
    const u16 offset = selector & 0xFFF8U;
    const auto descriptor = reinterpret_cast<const u8*>(gdtBase + offset);
    const u8 type = descriptor[5] & 0x0FU;
    // ia-32e guest state requires a present busy 64-bit tss descriptor. an
    // available tss would make vmlaunch fail with invalid guest state
    return type == 0xBU;
}

bool InitializeVmxFeatureContract() {
    // Capability MSRs and CET/XSS state are sampled per load. Reusing a
    // previous run's result after unload could pair a new guest with stale
    // host state if Windows changed CET or tracing configuration meanwhile.
    if (g_VcpuData == nullptr) {
        g_VmxFeatureContractInitialized = false;
        g_VmxFeatureContractValid = false;
        g_CetVmcsEnabled = 0;
        g_XsavesEnabled = 0;
        g_XstateMode = XstateSaveFxsave;
        g_XsavesMask = 0;
        g_EnumeratedXssMask = 0;
        g_SupportedXssMask = 0;
        g_GuestXssWriteMask = 0;
        g_HostXssMask = 0;
        g_HostXcr0Mask = 0;
        g_DebugctlMask = kDebugctlArchitecturalMask;
        g_XsaveStateSize = 0;
        g_VmxCapabilityProfile = 0;
        InterlockedExchange(&g_VmxGuestOptionalProfile, 0);
        InterlockedExchange(&g_VmxGuestOptionalProfileCandidate, 0);
    }
    if (g_VmxFeatureContractInitialized) {
        return g_VmxFeatureContractValid;
    }
    g_VmxFeatureContractInitialized = true;
    g_VmxFeatureContractValid = false;
    g_CetVmcsEnabled = 0;
    g_XsavesEnabled = 0;
    g_XstateMode = XstateSaveFxsave;
    g_XsavesMask = 0;
    g_EnumeratedXssMask = 0;
    g_SupportedXssMask = 0;
    g_GuestXssWriteMask = 0;
    g_HostXssMask = 0;
    g_HostXcr0Mask = 0;
    g_DebugctlMask = GetDebugctlCapabilityMask();
    g_XsaveStateSize = 0;
    g_VmxCapabilityProfile = 0;
    InterlockedExchange(&g_VmxGuestOptionalProfile, 0);
    InterlockedExchange(&g_VmxGuestOptionalProfileCandidate, 0);

    int regs[4] = {};
    __cpuid(regs, 0);
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);

    u64 vmxBasic = 0;
    if (!ReadMsrSafe(MSR_IA32_VMX_BASIC, &vmxBasic)) return false;
    const u64 currentCr4 = __readcr4();
    int leaf1[4] = {};
    __cpuidex(leaf1, 1, 0);
    const bool xsaveEnumerated =
        (static_cast<u32>(leaf1[2]) & CPUID_1_ECX_XSAVE) != 0;
    const bool osxsaveEnabled =
        (static_cast<u32>(leaf1[2]) & CPUID_1_ECX_OSXSAVE) != 0;
    const bool cr4OsxsaveEnabled = (currentCr4 & CR4_OSXSAVE) != 0;
    const bool fxsrEnumerated =
        (static_cast<u32>(leaf1[3]) & CPUID_1_EDX_FXSR) != 0;

    // Keep a real legacy backend for old VMX processors. It saves only the
    // architectural FPU/SSE image and never executes XGETBV or IA32_XSS.
    if (maxBasicLeaf < 0xD || !xsaveEnumerated || !osxsaveEnabled ||
        !cr4OsxsaveEnabled) {
        if (!fxsrEnumerated || (currentCr4 & CR4_OSFXSR) == 0 ||
            (currentCr4 & CR4_OSXSAVE) != 0 ||
            (currentCr4 & CR4_CET) != 0 ||
            (currentCr4 & CR4_FRED) != 0 ||
            (currentCr4 & CR4_PKE) != 0) {
            return false;
        }
        g_XstateMode = XstateSaveFxsave;
        g_XsavesEnabled = 0;
        g_XsavesMask = 0;
        g_EnumeratedXssMask = 0;
        g_SupportedXssMask = 0;
        g_GuestXssWriteMask = 0;
        g_HostXssMask = 0;
        g_HostXcr0Mask = 0;
        g_XsaveStateSize = FXSAVE_AREA_SIZE;
        g_VmxCapabilityProfile = BuildVmxCapabilityProfile(vmxBasic, false, false);
        g_VmxFeatureContractValid = true;
        return true;
    }

    g_VmxCapabilityProfile = BuildVmxCapabilityProfile(vmxBasic, false, false);

    u64 hostXcr0 = 0;
    __try {
        hostXcr0 = _xgetbv(0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    __cpuidex(regs, 0xD, 0);
    const u64 supportedXcr0 = static_cast<u32>(regs[0]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    if ((supportedXcr0 & 0x3ULL) != 0x3ULL ||
        (hostXcr0 & ~supportedXcr0) != 0 ||
        (hostXcr0 & 0x3ULL) != 0x3ULL) {
        return false;
    }
    if ((currentCr4 & CR4_PKE) != 0 && (hostXcr0 & XCR0_PKRU) == 0) {
        return false;
    }

    __cpuidex(regs, 0xD, 1);
    // Intel defines EAX[3] as the paired XSAVES/XRSTORS capability. EAX[4]
    // is XFD and must not be interpreted as an XRSTORS capability bit.
    const bool xsavesInstruction = (regs[0] & CPUID_D1_XSAVES) != 0;
    const bool xrstorsInstruction = xsavesInstruction;
    const bool xfdInstruction = (regs[0] & CPUID_D1_XFD) != 0;
    const u32 xsavesSize = static_cast<u32>(regs[1]);
    // XCOMP_BV bit 63 is reserved. Keep it out even if broken firmware reports
    // it in the XSS enumeration, because XRSTORS treats it as the compacted
    // format marker rather than a state-component selector.
    const u64 enumeratedXss = (static_cast<u32>(regs[2]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32)) &
                             ~(1ULL << 63);
    g_EnumeratedXssMask = enumeratedXss;

    u64 hostXss = 0;
    const bool xssRead = ReadMsrSafe(MSR_IA32_XSS, &hostXss);
    if (xsavesInstruction && !xssRead) return false;
    if (xssRead && (hostXss & ~enumeratedXss) != 0) return false;
    // a late launch must preserve every supervisor component selected by Windows
    if ((hostXss & ~IA32_XSS_PRESERVABLE_MASK) != 0) {
        return false;
    }

    HV_PASSIVE_PRINT("[HV] XSTATE contract: XSAVES=%u XRSTORS=%u XFD=%u D1.EBX=%lu "
             "XSS_ENUM=0x%llX HOST_XSS=0x%llX\n",
             xsavesInstruction ? 1U : 0U,
             xrstorsInstruction ? 1U : 0U,
             xfdInstruction ? 1U : 0U,
             static_cast<ULONG>(xsavesSize), enumeratedXss, hostXss);
    if (xsavesInstruction != xrstorsInstruction) return false;

    // an IPT XSS component can remain selected after VMXON only when this CPU
    // advertises PT support in VMX operation. The guest PT surface stays hidden.
    if ((hostXss & IA32_XSS_IPT) != 0) {
        u64 vmxMisc = 0;
        u64 ptControl = 0;
        if (!ReadMsrSafe(MSR_IA32_VMX_MISC, &vmxMisc) ||
            !ReadMsrSafe(MSR_IA32_RTIT_CTL, &ptControl)) {
            HV_PASSIVE_PRINT("[HV] Intel PT/XSS gate rejected: capability read failed\n");
            return false;
        }
        if ((vmxMisc & VMX_MISC_INTEL_PT) == 0) {
            HV_PASSIVE_PRINT("[HV] Intel PT/XSS gate rejected: VMX_MISC lacks post-VMXON PT\n");
            return false;
        }
        if ((ptControl & IA32_RTIT_CTL_TRACEEN) != 0) {
            HV_PASSIVE_PRINT("[HV] Intel PT/XSS gate rejected: tracing is active\n");
            return false;
        }
    }

    // the host selector is sampled independently from the immutable frame
    // contract. a guest may change its virtual selector without changing the
    // XSAVES layout used by the VM-exit assembly
    g_HostXssMask = hostXss;
    g_HostXcr0Mask = hostXcr0;

    const bool secondaryControlsUsable =
        (g_VmxCapabilityProfile & VmxProfileSecondaryControls) != 0;
    if (xsavesInstruction && xssRead && secondaryControlsUsable &&
        VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                          SECONDARY_ENABLE_XSAVES)) {
        // late launch begins with the live Windows selector, so the fixed frame
        // must preserve every selected component rather than the guest policy
        const u64 fixedXssMask = hostXss;
        if ((fixedXssMask & ~enumeratedXss) != 0 ||
            (fixedXssMask & ~IA32_XSS_PRESERVABLE_MASK) != 0) {
            return false;
        }

        u64 computedXssCapabilities = 0;
        if (!ComputeXsaveAreaSize(hostXcr0, fixedXssMask,
                                   &computedXssCapabilities,
                                   &g_XsaveStateSize) ||
            (fixedXssMask & ~computedXssCapabilities) != 0 ||
            g_XsaveStateSize != xsavesSize) {
            return false;
        }
        g_XsavesEnabled = 1;
    } else if (hostXss != 0) {
        // Ordinary XSAVE cannot preserve IA32_XSS-selected components.
        return false;
    }

    if (!g_XsavesEnabled) {
        __cpuidex(regs, 0xD, 0);
        g_XsaveStateSize = static_cast<u32>(regs[1]);
        g_XstateMode = XstateSaveXsave;
        g_SupportedXssMask = 0;
    } else {
        g_XstateMode = XstateSaveXsaves;
    }

    // the frame mask is immutable for this VMX run and represents preservation,
    // not the current guest selector
    g_XsavesMask = g_XsavesEnabled
                        ? g_HostXssMask
                        : 0;
    // expose only supervisor components that the fixed frame can restore. this
    // includes the initial host selector, so CPUID and WRMSR share one contract
    g_SupportedXssMask =
        g_XsavesEnabled
            ? (g_XsavesMask & enumeratedXss & IA32_XSS_PRESERVABLE_MASK)
            : 0;
    g_GuestXssWriteMask = g_SupportedXssMask;

    if (g_XsaveStateSize == 0 || g_XsaveStateSize > VMEXIT_XSAVE_MAX) {
        return false;
    }

    HV_PASSIVE_PRINT("[HV] XSTATE preservation: XSAVES=%u HOST_XSS=0x%llX "
             "PRESERVE_XSS=0x%llX GUEST_INITIAL_XSS=0x%llX "
             "GUEST_WRITE_XSS=0x%llX frame=%lu D1.EBX=%lu\n",
             g_XsavesEnabled ? 1U : 0U,
             g_HostXssMask, g_XsavesMask, g_HostXssMask,
             g_GuestXssWriteMask, static_cast<ULONG>(g_XsaveStateSize),
             static_cast<ULONG>(xsavesSize));

    // CR4.CET is set on current Windows 11 builds even when supervisor CET
    // is inactive.  In that state VMX still requires the paired CET
    // entry/exit controls and valid zeroed VMCS CET fields.
    if ((currentCr4 & CR4_CET) != 0) {
        const u32 exitMsr = ControlMsr(vmxBasic,
                                       MSR_IA32_VMX_EXIT_CTLS,
                                       MSR_IA32_VMX_TRUE_EXIT_CTLS);
        const u32 entryMsr = ControlMsr(vmxBasic,
                                        MSR_IA32_VMX_ENTRY_CTLS,
                                        MSR_IA32_VMX_TRUE_ENTRY_CTLS);
        if (!VmxControlAllows(exitMsr, VM_EXIT_LOAD_CET_STATE) ||
            !VmxControlAllows(entryMsr, VM_ENTRY_LOAD_CET_STATE)) {
            return false;
        }
        g_CetVmcsEnabled = 1;
    }

    g_VmxCapabilityProfile = BuildVmxCapabilityProfile(
        vmxBasic, g_XsavesEnabled != 0, g_CetVmcsEnabled != 0);

    HV_PASSIVE_PRINT("[HV] VMX control contract: profile=0x%X CET_VMCS=%u XSAVES=%u\n",
             g_VmxCapabilityProfile, g_CetVmcsEnabled ? 1U : 0U,
             g_XsavesEnabled ? 1U : 0U);

    g_VmxFeatureContractValid = true;
    return true;
}

// tags for memory allocation (avoid multi-char warnings by using integers)
constexpr u32 TAG_HV00 = 0x30305648; // 'HV00' little endian
constexpr u32 TAG_HVST = 0x54535648; // 'HVST' little endian
constexpr u32 TAG_HVCB = 0x42435648; // 'HVCB' little endian
constexpr u32 TAG_HVTR = 0x52545648; // 'HVTR' little endian
constexpr u32 TAG_HVID = 0x44495648; // HVID in little endian
static constexpr u64 kHvCrashBlobSignature = 0x48564342524D5541; // HVCBRMA
static constexpr u32 kHvCrashBlobVersion = 14;
static const GUID kHvCrashBlobGuid = {
    0xC6A3D9F0, 0x2F6F, 0x4E4A,
    {0xA5, 0x9E, 0x61, 0x34, 0x12, 0x88, 0x4B, 0xE6}
};
static constexpr const char kHvCrashBlobComponent[] = "Nested_HV_CrashBlob";

struct HvFatalSnapshot {
    u32 Cpu;
    u32 Lifecycle;
    u32 LaunchStage;
    u32 VmInstructionError;
    u32 VmExitCount;
    u32 VmcsSetupPhase;
    u32 VmcsCurrentState;
    u32 FirstExitProbeState;
    u32 FirstExitProbeBaselineVmExits;
    u32 FirstExitProbeBaselineVmResumes;
    u32 FirstExitProbeObservedVmExits;
    u32 FirstExitProbeObservedVmResumes;
    u32 FirstExitProbeReason;
    u32 FirstExitProbeAction;
    u32 FatalSnapshotCommitState;
    u64 LaunchFlags;
    u64 FirstExitProbeResumeFlags;

    u64 ExitReasonRaw;
    u64 ExitMsrIndex;
    u64 ExitMsrValue;
    u64 ExitQualification;

    u64 GuestRip;
    u64 GuestRsp;
    u64 GuestRflags;

    u64 GuestCr0;
    u64 GuestCr3;
    u64 GuestCr4;
    u64 GuestCr2;
    u64 LaunchRawGuestCr3;
    u64 LaunchGuestCr3;
    u64 LaunchRawHostCr3;
    u64 LaunchHostCr3;
    u64 LaunchCr3Metadata;

    u64 GuestInterruptibility;
    u64 GuestActivity;
    u64 EntryIntrInfo;
    u64 EntryIntrError;
    u64 EntryInstructionLength;
    u64 ExitIntrInfo;
    u64 ExitIntrError;
    u64 IdtVectoringInfo;
    u64 IdtVectoringError;

    u64 GuestXcr0;
    u64 GuestXss;
    u64 GuestEfer;
    u64 GuestPat;
    u64 GuestDebugctl;
    u64 GuestSCet;
    u64 GuestSsp;
    u64 GuestInterruptSspTable;
    u64 GuestPtCtl;

    u64 VmInstructionRflags;
    u32 NativeTeardownRejectMask;
    u32 VmcsReadFailed;
    u32 VmcsValueMismatch;
    u32 VmcsFailureCommitState;
    u32 VmcsFailureReason;
    u64 VmcsFailureArg0;
    u64 VmcsFailureArg1;
    u64 DiagnosticValidity;
    u64 FirstVmcsReadField;
    u64 FirstVmcsReadFlags;
    u64 FirstVmcsReadError;
    u64 FirstVmcsMismatchField;
    u64 FirstVmcsMismatchExpected;
    u64 FirstVmcsMismatchActual;
    u64 FirstVmcsMismatchMask;
    u64 FirstVmcsWriteField;
    u64 FirstVmcsWriteFlags;
    u64 FirstVmcsWriteError;
    // this is the last VMCS clear result, including a synthetic CF on pointer
    // mismatch or an unavailable current VMCS
    u64 VmcsClearFlags;
    // bit 63 marks a committed first-wins sample; the low RFLAGS bits retain
    // the VMfailInvalid or VMfailValid status from the assembly VMXOFF path
    u64 VmxOffFailureFlags;

    u32 LaunchDescriptorRejectMask;
    u32 XsetbvExitCount;
    u32 XssWriteExitCount;
    u32 XssWriteRejectCount;
    u64 LaunchDescriptorSelectorsLow;
    u64 LaunchDescriptorSelectorsHigh;
    u64 LaunchDescriptorGdtBase;
    u64 LaunchDescriptorIdtBase;
    u64 LaunchDescriptorTssBase;
    u64 LastXsetbvPrevious;
    u64 LastXsetbvRequested;
    u64 LastXssWritePrevious;
    u64 LastXssWriteRequested;
};

struct HvCrashBlob {
    u64 Signature;
    u32 Version;
    u32 CpuCount;
    u32 SnapshotCount;
    u32 Lifecycle;
    u64 BuildId;
    u32 ContractId;
    u32 Reserved;
    u64 BugcheckCode;
    u64 BugcheckArg1;
    u64 BugcheckArg2;
    u64 BugcheckArg3;
    u64 BugcheckArg4;
    u32 TraceRecordsPerCpu;
    u32 TraceReserved;
    u32 LaunchTelemetrySignature;
    u32 LaunchExpectedProcessors;
    u32 LaunchProbeEntered;
    u32 LaunchProbeCompleted;
    u32 LaunchDispatchEntered;
    u32 LaunchAssemblyEntered;
    u32 LaunchPrepareEntered;
    u32 LaunchPrepareSucceeded;
    u32 LaunchGuestEntered;
    u32 LaunchVmlaunchIssued;
    u32 LaunchVmlaunchReturned;
    u32 LaunchGuestStarted;
    u32 LaunchMarkedLaunched;
    u32 LaunchVmExitAsmReached;
    u32 LaunchFirstVmExitEntered;
    u32 LaunchDispatchReturned;
    u32 LaunchLastProbeProcessor;
    u32 LaunchLastDispatchProcessor;
    u32 LaunchLastPrepareProcessor;
    u32 LaunchLastReturnProcessor;
    HvHostFaultRecord HostFault;
    HvFatalSnapshot CpuSnapshots[1];
};

static KBUGCHECK_REASON_CALLBACK_RECORD g_HvBugCheckReasonRecord;
static bool g_HvBugCheckReasonRegistered = false;
static HvCrashBlob* g_HvCrashBlob = nullptr;
static SIZE_T g_HvCrashBlobSize = 0;
enum HvCrashBlobCaptureState : LONG {
    HvCrashBlobCaptureIdle = 0,
    HvCrashBlobCaptureWriting = 1,
    HvCrashBlobCaptureCommitted = 2,
};
static volatile LONG g_HvCrashBlobCaptured = 0;
static volatile LONG g_HvCrashBlobReleaseAuthorized = 0;
extern "C" volatile u64 g_HvVmxOffFailureFlagsAsm;

static __forceinline bool VmxOk(u64 rflags) {
    return ((rflags & 1ULL) == 0) && ((rflags & (1ULL << 6)) == 0);
}

// Intel defines exit qualification for ordinary exits and for entry-failure
// reasons 33 and 34 only.  Reason 41 and any future entry-failure reason leave
// this VMCS field unmodified, so it must not be published as current evidence
static __forceinline bool IsVmEntryFailureQualificationDefined(
    u32 rawReason) {
    if ((rawReason & 0x80000000U) == 0) return true;
    const u32 basicReason = rawReason & 0xFFFFU;
    return basicReason == VM_EXIT_REASON_INVALID_GUEST_STATE ||
           basicReason == VM_EXIT_REASON_MSR_LOADING;
}

enum VmcsSetupPhase : long {
    VmcsSetupPhaseNone = 0,
    VmcsSetupPhaseDescriptors = 1,
    VmcsSetupPhaseHostState = 2,
    VmcsSetupPhaseGuestState = 3,
    VmcsSetupPhaseExecutionControls = 4,
    VmcsSetupPhaseTertiaryControls = 5,
    VmcsSetupPhaseExitEntryControls = 6,
    VmcsSetupPhaseReadback = 7,
};

enum LaunchCheckStage : long {
    LaunchCheckNone = 0,
    LaunchCheckEntry = 1,
    LaunchCheckCpuidAndCr = 2,
    LaunchCheckXstate = 3,
    LaunchCheckCetAndPt = 4,
    LaunchCheckXsaveLayout = 5,
    LaunchCheckVmxProfile = 6,
    LaunchCheckRegions = 7,
    LaunchCheckVmxon = 8,
    LaunchCheckVmcs = 9,
    LaunchCheckXss = 10,
    LaunchCheckReady = 11,
    LaunchCheckException = 0x7FFF,
};

// LaunchStage is shared by the VMX owner and the stop rendezvous.  The
// handoff stage is deliberately distinct from GuestActive: a VcpuLaunched
// state alone only says that the wrapper is about to execute VMLAUNCH.
enum LaunchLifecycleStage : long {
    LaunchStageNone = 0,
    LaunchStageEntry = 1,
    LaunchStageVmxOn = 2,
    LaunchStageReady = 4,
    LaunchStageHandoff = 5,
    LaunchStageAbort = 6,
    LaunchStageParked = 7,
    LaunchStageTeardown = 8,
    LaunchStageStopped = 9,
    LaunchStageGuestActive = 10,
};

static __forceinline void SetVmcsSetupPhase(VcpuContext* vcpu,
                                             VmcsSetupPhase phase) {
    if (vcpu) {
        InterlockedExchange(&vcpu->VmcsSetupPhase, phase);
    }
}

static __forceinline long ReadVmcsFailureCommitState(
    const VcpuContext* vcpu) {
    if (!vcpu) return HvVmcsFailureEmpty;
    return InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->VmcsFailureCommitState), 0, 0);
}

static __forceinline u64 ReadVmcsFailureArg(const u64* value) {
    if (!value) return 0;
    return static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(const_cast<u64*>(value)), 0, 0));
}

// copy the first-wins record only when its commit word stays stable. A crash
// callback may run while a VMX-root callback is publishing the two arguments
// and must never expose a half-written tuple
static void ReadVmcsFailureRecord(const VcpuContext* vcpu,
                                  u32* commitState,
                                  u32* reason,
                                  u64* arg0,
                                  u64* arg1) {
    if (!commitState || !reason || !arg0 || !arg1) return;
    *commitState = static_cast<u32>(HvVmcsFailureEmpty);
    *reason = static_cast<u32>(HvVmcsFailureNone);
    *arg0 = 0;
    *arg1 = 0;
    if (!vcpu) return;

    const long firstCommit = ReadVmcsFailureCommitState(vcpu);
    *commitState = static_cast<u32>(firstCommit);
    if (firstCommit != HvVmcsFailureCommitted) return;

    MemoryBarrier();
    *reason = static_cast<u32>(InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->VmcsFailureReason), 0, 0));
    *arg0 = ReadVmcsFailureArg(&vcpu->VmcsFailureArg0);
    *arg1 = ReadVmcsFailureArg(&vcpu->VmcsFailureArg1);
    MemoryBarrier();

    const long finalCommit = ReadVmcsFailureCommitState(vcpu);
    if (firstCommit == finalCommit &&
        finalCommit == HvVmcsFailureCommitted) {
        return;
    }

    *commitState = static_cast<u32>(finalCommit);
    *reason = static_cast<u32>(HvVmcsFailureNone);
    *arg0 = 0;
    *arg1 = 0;
}

static void PublishVmcsFailure(VcpuContext* vcpu,
                               HvVmcsFailureReason reason,
                               u64 arg0 = 0,
                               u64 arg1 = 0) {
    if (!vcpu || reason == HvVmcsFailureNone) return;
    if (InterlockedCompareExchange(&vcpu->VmcsFailureCommitState,
                                   HvVmcsFailureWriting,
                                   HvVmcsFailureEmpty) !=
        HvVmcsFailureEmpty) {
        return;
    }
    vcpu->VmcsFailureArg0 = arg0;
    vcpu->VmcsFailureArg1 = arg1;
    InterlockedExchange(&vcpu->VmcsFailureReason,
                        static_cast<LONG>(reason));
    MemoryBarrier();
    InterlockedExchange(&vcpu->VmcsFailureCommitState,
                        HvVmcsFailureCommitted);
    WriteHvTrace(vcpu, CurrentProcessorIndex(), HvTraceEventContractFail,
                 static_cast<u64>(reason), arg0, arg1);
}

static __forceinline bool VmWriteChecked(u64 field, u64 value) {
    VcpuContext* vcpu = nullptr;
    if (g_VcpuData) {
        const u32 id = CurrentProcessorIndex();
        if (id < g_ProcessorCount) {
            vcpu = &g_VcpuData[id];
            if (InterlockedCompareExchange(&vcpu->VmcsWriteFailed, 0, 0) != 0) {
                return false;
            }
        }
    }
    const u64 flags = HvVmWrite(field, value);
    const bool success = VmxOk(flags);
    if (!success && vcpu) {
        // Publish the first failing field before exposing the failure latch.
        // A concurrent teardown reader therefore sees a complete diagnostic
        // record, never a partially initialized field/error tuple.
        if (InterlockedCompareExchange(&vcpu->VmcsWriteState, 1, 0) == 0) {
            u64 instructionError = ~0ULL;
            if ((flags & (1ULL << 6)) != 0) {
                const u64 readFlags =
                    HvVmReadChecked(VM_INSTRUCTION_ERROR, &instructionError);
                if (!VmxOk(readFlags)) instructionError = ~0ULL;
            }
            vcpu->FirstVmcsWriteField = field;
            vcpu->FirstVmcsWriteFlags = flags;
            vcpu->FirstVmcsWriteError = instructionError;
            MemoryBarrier();
            InterlockedExchange(&vcpu->VmcsWriteState, 2);
            PublishVmcsFailure(vcpu, HvVmcsFailureVmwrite, field, flags);
            InterlockedExchange(&vcpu->VmcsWriteFailed, 1);
        }
    }
    return success;
}

static __forceinline bool VmReadChecked(u64 field, u64* value) {
    if (!value) return false;
    const u64 flags = HvVmReadChecked(field, value);
    const bool success = VmxOk(flags);
    if (!success && g_VcpuData) {
        const u32 id = CurrentProcessorIndex();
        if (id < g_ProcessorCount) {
            VcpuContext* vcpu = &g_VcpuData[id];
            InterlockedOr64(reinterpret_cast<volatile LONG64*>(
                                &vcpu->VmcsDiagnosticValidity),
                            static_cast<LONG64>(HvVmcsValidityVmcsReadFailure));
            if (InterlockedCompareExchange(&vcpu->VmcsReadState, 1, 0) == 0) {
                u64 instructionError = ~0ULL;
                // vm instruction error is defined only for VMfailValid. do
                // not issue a recursive read when that field itself failed
                if ((flags & (1ULL << 6)) != 0 &&
                    field != VM_INSTRUCTION_ERROR) {
                    const u64 readFlags =
                        HvVmReadChecked(VM_INSTRUCTION_ERROR, &instructionError);
                    if (!VmxOk(readFlags)) instructionError = ~0ULL;
                }
                vcpu->FirstVmcsReadField = field;
                vcpu->FirstVmcsReadFlags = flags;
                vcpu->FirstVmcsReadError = instructionError;
                MemoryBarrier();
                InterlockedExchange(&vcpu->VmcsReadState, 2);
                PublishVmcsFailure(vcpu, HvVmcsFailureVmread, field, flags);
                InterlockedExchange(&vcpu->VmcsReadFailed, 1);
            } else {
                InterlockedExchange(&vcpu->VmcsReadFailed, 1);
            }
        }
    }
    return success;
}

static __forceinline u64 ReadVmcsDiagnosticValidity(
    const VcpuContext* vcpu) {
    if (!vcpu) return HvVmcsValidityNone;
    return static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(
            const_cast<u64*>(&vcpu->VmcsDiagnosticValidity)),
        0, 0));
}

static __forceinline void SetVmcsDiagnosticValidity(VcpuContext* vcpu,
                                                    u64 bits) {
    if (!vcpu || bits == HvVmcsValidityNone) return;
    InterlockedOr64(reinterpret_cast<volatile LONG64*>(
                        &vcpu->VmcsDiagnosticValidity),
                    static_cast<LONG64>(bits));
}

static __forceinline void ClearVmcsDiagnosticValidity(VcpuContext* vcpu,
                                                      u64 bits) {
    if (!vcpu || bits == HvVmcsValidityNone) return;
    const auto target = reinterpret_cast<volatile LONG64*>(
        &vcpu->VmcsDiagnosticValidity);
    LONG64 current = InterlockedCompareExchange64(target, 0, 0);
    for (;;) {
        const LONG64 updated = current & ~static_cast<LONG64>(bits);
        const LONG64 observed = InterlockedCompareExchange64(
            target, updated, current);
        if (observed == current) return;
        current = observed;
    }
}

static __forceinline bool VmcsValueMatches(VcpuContext* vcpu, u64 field,
                                            u64 actual, u64 expected,
                                            u64 mask) {
    if ((actual & mask) == (expected & mask)) return true;
    if (vcpu &&
        InterlockedCompareExchange(&vcpu->VmcsMismatchState, 1, 0) == 0) {
        vcpu->FirstVmcsMismatchField = field;
        vcpu->FirstVmcsMismatchExpected = expected;
        vcpu->FirstVmcsMismatchActual = actual;
        vcpu->FirstVmcsMismatchMask = mask;
        MemoryBarrier();
        InterlockedExchange(&vcpu->VmcsMismatchState, 2);
        PublishVmcsFailure(vcpu, HvVmcsFailureMismatch, field, actual);
        InterlockedExchange(&vcpu->VmcsValueMismatch, 1);
        WriteHvTrace(vcpu, CurrentProcessorIndex(), HvTraceEventContractFail,
                     field, expected, actual, mask);
    }
    return false;
}

static __forceinline bool IsFixedCrValueValid(u64 value, u32 fixed0Msr,
                                               u32 fixed1Msr) {
    u64 fixed0 = 0;
    u64 fixed1 = 0;
    return ReadMsrSafe(fixed0Msr, &fixed0) && ReadMsrSafe(fixed1Msr, &fixed1) &&
           (value & fixed0) == fixed0 && (value & ~fixed1) == 0;
}

static __forceinline u64 GetCr4GuestHostMask() {
    // A live Windows kernel has already committed its CR4 contract before
    // this driver loads. HyperDbg keeps both guest/host masks at zero; doing
    // the same avoids trapping ordinary CR4 updates or synthesizing a view
    // that differs from the native coordinator processor.
    return 0;
}

static __forceinline bool IsCanonical(u64 value) {
    // Windows normally uses 48-bit virtual addresses, but recent Intel
    // systems can enable LA57.  Use the architectural linear-address width
    // reported by CPUID so a valid 57-bit kernel pointer is not mistaken for
    // malformed state during teardown.
    u8 bits = g_LinearAddressBits;
    if (bits < 48 || bits > 57) bits = 48;
    const u64 signBit = 1ULL << (bits - 1);
    const u64 upperMask = ~((1ULL << bits) - 1ULL);
    return (value & signBit) ? ((value & upperMask) == upperMask)
                             : ((value & upperMask) == 0);
}

#pragma pack(push, 1)
struct HvIdtGate64 {
    u16 OffsetLow;
    u16 Selector;
    u8 Ist;
    u8 TypeAttributes;
    u16 OffsetMiddle;
    u32 OffsetHigh;
    u32 Reserved;
};
#pragma pack(pop)

static_assert(sizeof(HvIdtGate64) == 16,
              "64-bit IDT gates must remain 16 bytes");

static __forceinline void SetVmxHostIdtHandler(HvIdtGate64* gate,
                                                void (*handler)()) {
    if (!gate || !handler) return;
    const u64 address = reinterpret_cast<u64>(handler);
    gate->OffsetLow = static_cast<u16>(address & 0xFFFFULL);
    gate->OffsetMiddle = static_cast<u16>((address >> 16) & 0xFFFFULL);
    gate->OffsetHigh = static_cast<u32>(address >> 32);

    // match HyperDbg's current private-host-IDT model when no dedicated IST
    // stack is configured. A uniform no-IST frame also lets the raw assembly
    // recorder compute the interrupted RSP without guessing Windows' per-vector
    // IST policy.
    gate->Ist = 0;
}

static bool PrepareVmxHostIdt(VcpuContext* vcpu, u64 nativeIdtBase,
                              u16 nativeIdtLimit, u32 cpuId) {
    if (!vcpu || !vcpu->VmxHostIdt || !IsCanonical(nativeIdtBase)) {
        return false;
    }

    constexpr SIZE_T kMinimumExceptionIdtBytes = 32 * sizeof(HvIdtGate64);
    SIZE_T copyBytes = static_cast<SIZE_T>(nativeIdtLimit) + 1;
    if (copyBytes < kMinimumExceptionIdtBytes) return false;
    if (copyBytes > PAGE_SIZE) copyBytes = PAGE_SIZE;

    RtlZeroMemory(vcpu->VmxHostIdt, PAGE_SIZE);
    RtlCopyMemory(vcpu->VmxHostIdt,
                  reinterpret_cast<const void*>(nativeIdtBase), copyBytes);

    auto* idt = static_cast<HvIdtGate64*>(vcpu->VmxHostIdt);
    // Keep Windows' selector, gate type, DPL and IST choice. Only replace the
    // synchronous exception targets that can hide a VMX-root failure behind a
    // reset or a recursive kernel exception on the private host stack.
    SetVmxHostIdtHandler(&idt[0], HvHostException0);
    // HyperDbg does not let a VMX-root NMI fall straight into the Windows NMI
    // entry path. V49 is an isolation build: consume only NMIs that arrive
    // while this processor is already in VMX root, count them, and return.
    // Guest NMIs are unaffected because NMI exiting remains disabled. Once
    // this proves or disproves the root-NMI hypothesis, the diagnostic sink
    // can be replaced with proper guest NMI reinjection.
    SetVmxHostIdtHandler(&idt[2], HvHostNmi2);
    SetVmxHostIdtHandler(&idt[5], HvHostException5);
    SetVmxHostIdtHandler(&idt[6], HvHostException6);
    SetVmxHostIdtHandler(&idt[7], HvHostException7);
    SetVmxHostIdtHandler(&idt[8], HvHostException8);
    SetVmxHostIdtHandler(&idt[10], HvHostException10);
    SetVmxHostIdtHandler(&idt[11], HvHostException11);
    SetVmxHostIdtHandler(&idt[12], HvHostException12);
    SetVmxHostIdtHandler(&idt[13], HvHostException13);
    SetVmxHostIdtHandler(&idt[14], HvHostException14);
    SetVmxHostIdtHandler(&idt[16], HvHostException16);
    SetVmxHostIdtHandler(&idt[17], HvHostException17);
    SetVmxHostIdtHandler(&idt[18], HvHostException18);
    SetVmxHostIdtHandler(&idt[19], HvHostException19);
    SetVmxHostIdtHandler(&idt[21], HvHostException21);

    vcpu->VmxHostIdtBase = reinterpret_cast<u64>(vcpu->VmxHostIdt);
    if (!IsCanonical(vcpu->VmxHostIdtBase)) return false;

    WriteHvTrace(vcpu, cpuId, HvTraceEventHostIdtReady,
                 nativeIdtBase, vcpu->VmxHostIdtBase, nativeIdtLimit,
                 static_cast<u64>(copyBytes));
    return true;
}

static __forceinline bool IsValidPatValue(u64 value) {
    // IA32_PAT has eight 8-bit memory-type entries.  Only 0, 1, 4, 5, 6 and
    // 7 are architecturally valid; all other encodings (including 2/3 and
    // bytes with high bits set) are reserved.  Putting one into the VMCS
    // guest PAT field makes the next VM-entry fail, so reject it as guest #GP.
    for (u32 i = 0; i < 8; ++i) {
        const u8 type = static_cast<u8>((value >> (i * 8)) & 0xFFU);
        if (type != 0 && type != 1 && type != 4 && type != 5 &&
            type != 6 && type != 7) return false;
    }
    return true;
}

static __forceinline bool IsValidIa32eEfer(u64 value, u64 cr0) {
    // VM-entry loads only accept the architectural IA32_EFER bits.  The
    // late-launch contract always enters a 64-bit Windows context, so LME,
    // LMA, and paging must already agree before the value reaches the VMCS.
    constexpr u64 kArchitecturalEferMask =
        EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
    constexpr u64 kCr0Paging = 1ULL << 31;
    return (value & ~kArchitecturalEferMask) == 0 &&
           (value & (EFER_LME | EFER_LMA)) ==
               (EFER_LME | EFER_LMA) &&
           (cr0 & kCr0Paging) != 0;
}

static __forceinline bool IsValidDebugctl(u64 value) {
    return (value & ~g_DebugctlMask) == 0;
}

static u64 GetDebugctlCapabilityMask() {
    u64 mask = kDebugctlArchitecturalMask;
    int regs[4] = {};
    __cpuid(regs, 0);
    if (static_cast<u32>(regs[0]) < 7) {
        return mask & ~IA32_DEBUGCTL_BUS_LOCK_DETECT;
    }
    __cpuidex(regs, 7, 0);
    if ((static_cast<u32>(regs[3]) & (1U << 24)) == 0) {
        mask &= ~IA32_DEBUGCTL_BUS_LOCK_DETECT;
    }
    return mask;
}

static __forceinline bool IsValidCr3(u64 value, u64 cr4 = __readcr4()) {
    // CR3 is a physical address plus (when PCIDE is enabled) a 12-bit PCID.
    // Reject a null page-table base and bits above the processor's advertised
    // physical-address width before putting the value in the VMCS.
    int regs[4] = {};
    __cpuidex(regs, 0x80000000, 0);
    const u32 maxExtended = static_cast<u32>(regs[0]);
    u8 physicalBits = 52;
    if (maxExtended >= 0x80000008) {
        __cpuidex(regs, 0x80000008, 0);
        const u8 reported = static_cast<u8>(regs[0] & 0xFF);
        if (reported >= 32 && reported <= 52) physicalBits = reported;
    }
    const u64 physicalMask = (1ULL << physicalBits) - 1ULL;
    // With PCIDE clear, CR3[4:3] are PWT/PCD and all other low bits are
    // reserved. With PCIDE set, the complete low 12 bits are a PCID.
    const bool pcide = (cr4 & CR4_PCIDE) != 0;
    const u64 lowMask = pcide ? 0xFFFULL : 0x018ULL;
    // With PCIDE set, CR3[63] is the architected no-flush hint. It is not
    // part of the physical base and must not be rejected as a reserved bit.
    const u64 noFlushMask = pcide ? (1ULL << 63) : 0;
    const u64 baseMask = physicalMask & ~0xFFFULL;
    const u64 allowedMask = baseMask | lowMask | noFlushMask;
    return (value & ~allowedMask) == 0 && (value & baseMask) != 0;
}

static __forceinline u64 NormalizeCr3(u64 value, u64 cr4) {
    // CR3[63] is a MOV-to-CR3 no-flush hint, not persistent architectural
    // state.  VMCS guest CR3 validation requires the reserved bit to be clear.
    return (cr4 & CR4_PCIDE) != 0 ? value & ~(1ULL << 63) : value;
}

static __forceinline u64 ReadLaunchCr3Field(const u64* field) {
    // A timed-out launch DPC can still publish this diagnostic while the
    // passive coordinator is reading it. Use an atomic 64-bit load so a
    // debugger sees one complete value instead of a torn pair of DWORDs.
    if (!field) return 0;
    return static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(const_cast<u64*>(field)), 0, 0));
}

static __forceinline u64 PackLaunchCr3Metadata(u64 rawGuestCr3,
                                                u64 rawHostCr3,
                                                u64 guestCr4,
                                                u64 hostCr4) {
    // retain PCID or PWT/PCD low bits and no-flush state beside the raw values
    // because a target DPC cannot safely emit formatted diagnostics
    constexpr u64 kCr3LowMask = 0xFFFULL;
    constexpr u64 kGuestLowShift = 8;
    constexpr u64 kHostLowShift = 20;
    constexpr u64 kGuestPcideShift = 32;
    constexpr u64 kHostPcideShift = 33;
    constexpr u64 kGuestNoFlushShift = 34;
    constexpr u64 kHostNoFlushShift = 35;
    const u64 irql = static_cast<u64>(KeGetCurrentIrql()) & 0xFFULL;
    const u64 guestLow = (rawGuestCr3 & kCr3LowMask) << kGuestLowShift;
    const u64 hostLow = (rawHostCr3 & kCr3LowMask) << kHostLowShift;
    const u64 guestPcide = (guestCr4 & CR4_PCIDE) != 0
                                ? 1ULL << kGuestPcideShift
                                : 0ULL;
    const u64 hostPcide = (hostCr4 & CR4_PCIDE) != 0
                               ? 1ULL << kHostPcideShift
                               : 0ULL;
    const u64 guestNoFlush = (rawGuestCr3 & (1ULL << 63)) != 0
                                 ? 1ULL << kGuestNoFlushShift
                                 : 0ULL;
    const u64 hostNoFlush = (rawHostCr3 & (1ULL << 63)) != 0
                                ? 1ULL << kHostNoFlushShift
                                : 0ULL;
    return irql | guestLow | hostLow | guestPcide | hostPcide |
           guestNoFlush | hostNoFlush;
}

static __forceinline bool IsValidArchitecturalCr3(u64 value, u64 cr4) {
    // The no-flush bit belongs only to a MOV-to-CR3 operand. It must never
    // survive in the architectural guest CR3 or in a teardown snapshot.
    return (value & (1ULL << 63)) == 0 && IsValidCr3(value, cr4);
}

static __forceinline bool IsValidGuestDr7(u64 value) {
    // DR7 is a 32-bit architectural register. Bit 10 is fixed to one and
    // bits 11 and 12 are reserved; rejecting them before native teardown
    // avoids a debug exception while the guest frame is being restored.
    constexpr u64 kDr7Reserved = (1ULL << 11) | (1ULL << 12) |
                                 (1ULL << 14) | (1ULL << 15);
    return (value & ~0xFFFFFFFFULL) == 0 &&
           (value & (1ULL << 10)) != 0 && (value & kDr7Reserved) == 0;
}

static __forceinline bool IsValidGuestState(const GuestContext* c) {
    if (!c || !IsCanonical(c->GuestRip) || !IsCanonical(c->GuestRsp)) {
        return false;
    }

    // The restore path writes the complete five-word 64-bit IRETQ frame and
    // its private spill below RSP. Reject values that would underflow it or point
    // at the low, unmapped portion of the address space. A kernel-mode Windows
    // stack is always well above this floor; this is intentionally conservative.
    if (c->GuestRsp < 0x200 || c->GuestRip < 0x10000) return false;

    // CR3 may carry a PCID in bits 11:0 when CR4.PCIDE is set (Windows uses
    // PCID/KPTI on current releases), so only reject a zero page-table base.
    if (!IsValidArchitecturalCr3(c->GuestCr3, c->GuestCr4)) {
        return false;
    }
    // In 64-bit mode IRETQ may restore a null SS when the target CPL is
    // not 3. The RPL comparison still applies; a null selector has RPL 0.
    if (c->GuestCs == 0 ||
        (c->GuestCs & 3) != (c->GuestSs & 3)) {
        return false;
    }

    // This driver has no safe ring-3 teardown path.  Keep the direct restore
    // sequence restricted to a 64-bit ring-0 Windows context and reject
    // malformed control/MSR state before it can reach MOV CRx or WRMSR.
    constexpr u64 kRequiredCr0Bits = (1ULL << 0) | (1ULL << 31);
    constexpr u64 kRequiredCr4Bits = 1ULL << 5;
    constexpr u64 kGuestEferBits = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
    if ((c->GuestCs & 3) != 0 || (c->GuestSs & 3) != 0 ||
        !IsFixedCrValueValid(c->GuestCr0, MSR_IA32_VMX_CR0_FIXED0,
                             MSR_IA32_VMX_CR0_FIXED1) ||
        !IsFixedCrValueValid(c->GuestCr4, MSR_IA32_VMX_CR4_FIXED0,
                             MSR_IA32_VMX_CR4_FIXED1) ||
        (c->GuestCr0 & kRequiredCr0Bits) != kRequiredCr0Bits ||
        (c->GuestCr4 & kRequiredCr4Bits) != kRequiredCr4Bits ||
        (c->GuestEfer & ~kGuestEferBits) != 0 ||
        (c->GuestEfer & (EFER_LME | EFER_LMA)) !=
            (EFER_LME | EFER_LMA) ||
        !IsCanonical(c->GuestFsBase) || !IsCanonical(c->GuestGsBase) ||
        !IsCanonical(c->GuestKernelGsBase) ||
        c->GuestSysenterCs > 0xFFFFULL ||
        !IsCanonical(c->GuestSysenterEsp) ||
        !IsCanonical(c->GuestSysenterEip) ||
         !IsValidPatValue(c->GuestPat) ||
         !IsValidDebugctl(c->GuestDebugctl) ||
         !IsValidGuestDr7(c->GuestDr7)) {
        return false;
    }

    // XCR0 and IA32_XSS are not VMCS fields. Validate the saved selectors
    // against the immutable assembly save contract before an IRET handoff;
    // a mask mismatch would raise #GP in VMX root and can cascade to #DF.
    if (g_XstateMode == XstateSaveFxsave &&
        (c->GuestXcr0 != 0 || c->GuestXss != 0)) {
        return false;
    }
    if (g_XstateMode != XstateSaveFxsave &&
        ((c->GuestXcr0 & ~g_HostXcr0Mask) != 0 ||
         (g_XsavesEnabled && (c->GuestXss & ~g_XsavesMask) != 0) ||
         (!g_XsavesEnabled && c->GuestXss != 0))) {
        return false;
    }

    // RFLAGS bit 1 is architecturally fixed, while VM/VIF/VIP and the high
    // reserved bits must not be present in an IRET frame.
    constexpr u64 kRflagsAllowed = (1ULL << 0) | (1ULL << 1) |
                                    (1ULL << 2) | (1ULL << 4) |
                                    (1ULL << 6) | (1ULL << 7) |
                                    (1ULL << 8) | (1ULL << 9) |
                                    (1ULL << 10) | (1ULL << 11) |
                                    (1ULL << 12) | (1ULL << 13) |
                                    (1ULL << 14) | (1ULL << 16) |
                                    (1ULL << 18) | (1ULL << 21);
    constexpr u64 kRflagsReserved = ~kRflagsAllowed;
    // IRETQ with NT set faults in IA-32e mode. Do not turn an observable VMX
    // failure into #GP while the processor is leaving the diagnostic path.
    constexpr u64 kRflagsNt = 1ULL << 14;
    if ((c->Rflags & (1ULL << 1)) == 0 ||
        (c->Rflags & kRflagsNt) != 0 ||
        (c->Rflags & kRflagsReserved) != 0) {
        return false;
    }
    return true;
}

static __forceinline long AcquireFatalSnapshotCommitState(VcpuContext* vcpu) {
    if (!vcpu) return HvFatalSnapshotCommitted;
    return InterlockedCompareExchange(&vcpu->FatalSnapshotCommitState,
                                      HvFatalSnapshotEmpty,
                                      HvFatalSnapshotEmpty);
}

static __forceinline u32 ReadNativeTeardownRejectMask(
    const VcpuContext* vcpu) {
    if (!vcpu) return HvNativeTeardownRejectNone;
    return static_cast<u32>(InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->NativeTeardownRejectMask), 0, 0));
}

static __forceinline long ReadFirstExitProbeState(
    const VcpuContext* vcpu) {
    if (!vcpu) return FirstExitProbeFailed;
    return InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->FirstExitProbeState), 0, 0);
}

static __forceinline u64 PackFirstExitProbeResult(long reason, long action) {
    return static_cast<u64>(static_cast<u32>(reason)) |
           (static_cast<u64>(static_cast<u32>(action)) << 32);
}

static void CaptureFirstExitProbeObservation(VcpuContext* vcpu,
                                             long reason,
                                             long action) {
    if (!vcpu) return;
    const long vmExits = InterlockedCompareExchange(&vcpu->VmExitCount, 0, 0);
    const long vmResumes =
        InterlockedCompareExchange(&vcpu->VmResumeAttempts, 0, 0);
    const u64 resumeFlags = static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&vcpu->LastVmResumeFlags), 0, 0));
    InterlockedExchange(&vcpu->FirstExitProbeObservedVmExits, vmExits);
    InterlockedExchange(&vcpu->FirstExitProbeObservedVmResumes, vmResumes);
    InterlockedExchange(&vcpu->FirstExitProbeReason, reason);
    InterlockedExchange(&vcpu->FirstExitProbeAction, action);
    InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&vcpu->FirstExitProbeResumeFlags),
        static_cast<LONG64>(resumeFlags));
    MemoryBarrier();
}

static void FailFirstExitProbeIfActive(VcpuContext* vcpu, u32 cpuId) {
    if (!vcpu) return;
    const long state = ReadFirstExitProbeState(vcpu);
    if (state != FirstExitProbeArmed &&
        state != FirstExitProbeVmExitEntered) {
        return;
    }
    const long reason = static_cast<long>(vcpu->LastExitReasonBasic);
    const long action = InterlockedCompareExchange(&vcpu->LastExitAction, 0, 0);
    CaptureFirstExitProbeObservation(vcpu, reason, action);
    if (InterlockedCompareExchange(&vcpu->FirstExitProbeState,
                                   FirstExitProbeFailed,
                                   state) == state) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(FirstExitProbeFailed),
                     static_cast<u64>(InterlockedCompareExchange(
                         &vcpu->FirstExitProbeObservedVmExits, 0, 0)),
                     static_cast<u64>(InterlockedCompareExchange(
                         &vcpu->FirstExitProbeObservedVmResumes, 0, 0)),
                     PackFirstExitProbeResult(reason, action));
    }
}

static void InvalidateValidatedFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
    if (!vcpu ||
        InterlockedCompareExchange(&vcpu->FirstExitProbeState,
                                    FirstExitProbeFailed,
                                    FirstExitProbeExitValidated) !=
            FirstExitProbeExitValidated) {
        return;
    }

    const long observedExits = InterlockedCompareExchange(
        &vcpu->FirstExitProbeObservedVmExits, 0, 0);
    const long observedResumes = InterlockedCompareExchange(
        &vcpu->FirstExitProbeObservedVmResumes, 0, 0);
    const long reason = InterlockedCompareExchange(
        &vcpu->FirstExitProbeReason, 0, 0);
    const long action = InterlockedCompareExchange(
        &vcpu->FirstExitProbeAction, 0, 0);
    WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                 static_cast<u64>(FirstExitProbeFailed),
                 static_cast<u64>(observedExits),
                 static_cast<u64>(observedResumes),
                 PackFirstExitProbeResult(reason, action));
}

static void FailFirstExitProbeAtFatalBoundary(VcpuContext* vcpu, u32 cpuId) {
    FailFirstExitProbeIfActive(vcpu, cpuId);
    InvalidateValidatedFirstExitProbe(vcpu, cpuId);
}

static void MarkFirstExitProbeVmExitEntered(VcpuContext* vcpu,
                                             u32 cpuId,
                                             u32 reason) {
    if (!vcpu) return;
    if (InterlockedCompareExchange(&vcpu->FirstExitProbeState,
                                   FirstExitProbeVmExitEntered,
                                   FirstExitProbeArmed) ==
        FirstExitProbeArmed) {
        InterlockedExchange(&vcpu->FirstExitProbeReason,
                            static_cast<LONG>(reason));
        MemoryBarrier();
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(FirstExitProbeVmExitEntered), reason,
                     static_cast<u64>(InterlockedCompareExchange(
                         &vcpu->VmExitCount, 0, 0)), 0);
    }
}

static void CompleteFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
    if (!vcpu || ReadFirstExitProbeState(vcpu) !=
                     FirstExitProbeVmExitEntered) {
        return;
    }
    const long baselineExits = InterlockedCompareExchange(
        &vcpu->FirstExitProbeBaselineVmExits, 0, 0);
    const long baselineResumes = InterlockedCompareExchange(
        &vcpu->FirstExitProbeBaselineVmResumes, 0, 0);
    const long reason = static_cast<long>(vcpu->LastExitReasonBasic);
    const long action = InterlockedCompareExchange(&vcpu->LastExitAction, 0, 0);
    CaptureFirstExitProbeObservation(vcpu, reason, action);
    const long observedExits = InterlockedCompareExchange(
        &vcpu->FirstExitProbeObservedVmExits, 0, 0);
    const long observedResumes = InterlockedCompareExchange(
        &vcpu->FirstExitProbeObservedVmResumes, 0, 0);
    const u64 resumeFlags = static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&vcpu->FirstExitProbeResumeFlags),
        0, 0));
    // an interrupt or another ordinary exit may be serviced between arming
    // the token and the sentinel CPUID. Validate the target transaction
    // relative to the arm baseline without assuming it was the only exit
    const bool valid = observedExits >= baselineExits + 1 &&
        observedResumes >= baselineResumes &&
        reason == static_cast<long>(VM_EXIT_REASON_CPUID) &&
        action == kExitActionResume && resumeFlags == 0;
    const long outcome = valid ? FirstExitProbeExitValidated
                               : FirstExitProbeFailed;
    if (InterlockedCompareExchange(&vcpu->FirstExitProbeState, outcome,
                                   FirstExitProbeVmExitEntered) ==
        FirstExitProbeVmExitEntered) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(outcome),
                     static_cast<u64>(observedExits),
                     static_cast<u64>(observedResumes),
                     PackFirstExitProbeResult(reason, action));
    }
}

static bool ArmFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
    if (!vcpu) return false;
    const u64 priorResumeFlags = static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&vcpu->LastVmResumeFlags), 0, 0));
    const long baselineExits =
        InterlockedCompareExchange(&vcpu->VmExitCount, 0, 0);
    const long baselineResumes =
        InterlockedCompareExchange(&vcpu->VmResumeAttempts, 0, 0);
    if (ReadFirstExitProbeState(vcpu) != FirstExitProbeIdle) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(FirstExitProbeFailed),
                     static_cast<u64>(baselineExits),
                     static_cast<u64>(baselineResumes), 0);
        return false;
    }
    if (priorResumeFlags != 0) {
        (void)InterlockedCompareExchange(&vcpu->FirstExitProbeState,
                                         FirstExitProbeFailed,
                                         FirstExitProbeIdle);
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(FirstExitProbeFailed),
                     static_cast<u64>(baselineExits),
                     static_cast<u64>(baselineResumes), priorResumeFlags);
        return false;
    }
    InterlockedExchange(&vcpu->FirstExitProbeBaselineVmExits, baselineExits);
    InterlockedExchange(&vcpu->FirstExitProbeBaselineVmResumes,
                        baselineResumes);
    InterlockedExchange(&vcpu->FirstExitProbeObservedVmExits, 0);
    InterlockedExchange(&vcpu->FirstExitProbeObservedVmResumes, 0);
    InterlockedExchange(&vcpu->FirstExitProbeReason, 0);
    InterlockedExchange(&vcpu->FirstExitProbeAction, kExitActionNone);
    InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&vcpu->FirstExitProbeResumeFlags),
        0);
    MemoryBarrier();
    if (InterlockedCompareExchange(&vcpu->FirstExitProbeState,
                                   FirstExitProbeArmed,
                                   FirstExitProbeIdle) != FirstExitProbeIdle) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(FirstExitProbeFailed), 0, 0, 0);
        return false;
    }
    WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                 static_cast<u64>(FirstExitProbeArmed),
                 static_cast<u64>(baselineExits),
                 static_cast<u64>(baselineResumes), 0);
    return true;
}

static bool VerifyFirstExitProbeReturn(VcpuContext* vcpu, u32 cpuId,
                                       const int regs[4]) {
    if (!vcpu || !regs) return false;
    const long state = ReadFirstExitProbeState(vcpu);
    const long baselineExits = InterlockedCompareExchange(
        &vcpu->FirstExitProbeBaselineVmExits, 0, 0);
    const long baselineResumes = InterlockedCompareExchange(
        &vcpu->FirstExitProbeBaselineVmResumes, 0, 0);
    const long observedExits = InterlockedCompareExchange(
        &vcpu->FirstExitProbeObservedVmExits, 0, 0);
    const long observedResumes = InterlockedCompareExchange(
        &vcpu->FirstExitProbeObservedVmResumes, 0, 0);
    const long reason = InterlockedCompareExchange(&vcpu->FirstExitProbeReason,
                                                    0, 0);
    const long action = InterlockedCompareExchange(&vcpu->FirstExitProbeAction,
                                                    0, 0);
    const u64 resumeFlags = static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&vcpu->FirstExitProbeResumeFlags),
        0, 0));
    const bool magicTuple = static_cast<u32>(regs[0]) == kFirstExitProbeLeaf &&
        static_cast<u32>(regs[1]) == kFirstExitProbeEbx &&
        static_cast<u32>(regs[2]) == kFirstExitProbeEcx &&
        static_cast<u32>(regs[3]) == kFirstExitProbeEdx;
    const long currentExits = InterlockedCompareExchange(&vcpu->VmExitCount,
                                                          0, 0);
    const long currentResumes = InterlockedCompareExchange(
        &vcpu->VmResumeAttempts, 0, 0);
    const bool valid = state == FirstExitProbeExitValidated && magicTuple &&
        observedExits >= baselineExits + 1 &&
        observedResumes >= baselineResumes &&
        reason == static_cast<long>(VM_EXIT_REASON_CPUID) &&
        action == kExitActionResume && resumeFlags == 0 &&
        currentExits >= baselineExits + 1 &&
        currentResumes >= baselineResumes + 1;
    if (!valid) {
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                     static_cast<u64>(FirstExitProbeFailed),
                     static_cast<u64>(observedExits),
                     static_cast<u64>(observedResumes),
                     PackFirstExitProbeResult(reason, action));
        return false;
    }
    if (InterlockedCompareExchange(&vcpu->FirstExitProbeState,
                                   FirstExitProbeReturned,
                                   FirstExitProbeExitValidated) !=
        FirstExitProbeExitValidated) {
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return false;
    }
    WriteHvTrace(vcpu, cpuId, HvTraceEventFirstExitProbe,
                 static_cast<u64>(FirstExitProbeReturned),
                 static_cast<u64>(observedExits),
                 static_cast<u64>(observedResumes),
                 PackFirstExitProbeResult(reason, action));
    return true;
}

static bool RunFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
    if (!ArmFirstExitProbe(vcpu, cpuId)) return false;
    int regs[4] = {};
    __cpuidex(regs, static_cast<int>(kFirstExitProbeLeaf), 0);
    return VerifyFirstExitProbeReturn(vcpu, cpuId, regs);
}

static __forceinline void RequestFatalStop(GuestContext* c) {
    if (!c) return;
    c->AbortVm = 0;
    c->HaltVm = 1;
}

static __forceinline void RequestAuthenticatedUnload(GuestContext* c,
                                                     u32 exitReason) {
    const u32 id = CurrentProcessorIndex();
    VcpuContext* vcpu =
        g_VcpuData && id < g_ProcessorCount ? &g_VcpuData[id] : nullptr;
    const bool authenticatedUnload =
        c && exitReason == VM_EXIT_REASON_VMCALL &&
        (c->GuestCs & 3U) == 0 &&
        c->Rcx == HYPERVISOR_MAGIC && c->Rdx == VMCALL_UNLOAD;
    // Descriptor validation is needed only at the authenticated native
    // teardown boundary. Keeping it out of ordinary exits avoids a long run
    // of VMREADs on every CR3 or MSR transition.
    if (authenticatedUnload) {
        UpdateNativeTeardownContract(vcpu);
    }
    u32 rejectMask = ReadNativeTeardownRejectMask(vcpu);
    u64 entryIntrInfo = 0;
    u64 exitIntrInfo = 0;
    u64 idtVectoringInfo = 0;
    u64 guestInterruptibility = 0;
    u64 guestActivity = 0;
    u64 pendingDebug = 0;
    // VmExitHandler clears the one-shot VM-entry fields after taking its
    // snapshot. A live VMREAD here would therefore observe a different
    // transaction and could authorize native teardown while an event is still
    // being delivered. Consume only the published snapshot instead.
    bool eventStateKnown =
        vcpu && InterlockedCompareExchange(&vcpu->LastEventSnapshotValid,
                                           0, 0) != 0;
    if (eventStateKnown) {
        MemoryBarrier();
        entryIntrInfo = vcpu->LastVmEntryIntrInfo;
        exitIntrInfo = vcpu->LastVmExitIntrInfo;
        idtVectoringInfo = vcpu->LastIdtVectoringInfo;
        guestInterruptibility = vcpu->LastGuestInterruptibility;
        guestActivity = vcpu->LastGuestActivity;
        pendingDebug = vcpu->LastGuestPendingDbgExceptions;
        MemoryBarrier();
        if (InterlockedCompareExchange(&vcpu->LastEventSnapshotValid,
                                       0, 0) == 0) {
            eventStateKnown = false;
        }
    }
    if (!eventStateKnown) {
        rejectMask |= HvNativeTeardownRejectVmcsRead;
    } else {
        if ((entryIntrInfo & VM_ENTRY_INTR_INFO_VALID) != 0) {
            rejectMask |= HvNativeTeardownRejectVmEntryEvent;
        }
        if ((exitIntrInfo & VM_ENTRY_INTR_INFO_VALID) != 0) {
            rejectMask |= HvNativeTeardownRejectExitEvent;
        }
        if ((idtVectoringInfo & VM_ENTRY_INTR_INFO_VALID) != 0) {
            rejectMask |= HvNativeTeardownRejectIdtVectoring;
        }
        if (guestActivity != 0) {
            rejectMask |= HvNativeTeardownRejectActivity;
        }
        if (guestInterruptibility != 0) {
            rejectMask |= HvNativeTeardownRejectInterruptibility;
        }
        if (pendingDebug != 0) {
            rejectMask |= HvNativeTeardownRejectPendingDebug;
        }
    }
    const bool noPendingEvent =
        eventStateKnown &&
        (entryIntrInfo & VM_ENTRY_INTR_INFO_VALID) == 0 &&
        (exitIntrInfo & VM_ENTRY_INTR_INFO_VALID) == 0 &&
        (idtVectoringInfo & VM_ENTRY_INTR_INFO_VALID) == 0 &&
        guestInterruptibility == 0 && guestActivity == 0 &&
        pendingDebug == 0;
    if (!c || exitReason != VM_EXIT_REASON_VMCALL) {
        rejectMask |= HvNativeTeardownRejectParameters;
    }
    if (!c || (c->GuestCs & 3U) != 0) {
        rejectMask |= HvNativeTeardownRejectCpl;
    }
    if (!c || c->Rcx != HYPERVISOR_MAGIC || c->Rdx != VMCALL_UNLOAD) {
        rejectMask |= HvNativeTeardownRejectParameters;
    }
    const bool descriptorContractSafe =
        vcpu &&
        InterlockedCompareExchange(&vcpu->NativeTeardownSafe, 0, 0) != 0;
    constexpr u32 kDescriptorRejectBits =
        static_cast<u32>(HvNativeTeardownRejectSelector) |
        static_cast<u32>(HvNativeTeardownRejectCsSsLimitAr) |
        static_cast<u32>(HvNativeTeardownRejectGdt) |
        static_cast<u32>(HvNativeTeardownRejectIdt) |
        static_cast<u32>(HvNativeTeardownRejectTr) |
        static_cast<u32>(HvNativeTeardownRejectVmcsRead);
    if (!descriptorContractSafe &&
        (rejectMask & kDescriptorRejectBits) == 0) {
        rejectMask |= HvNativeTeardownRejectDescriptorContract;
    }
    const bool guestStateValid = IsValidGuestState(c);
    if (!guestStateValid) {
        rejectMask |= HvNativeTeardownRejectGuestState;
    }
    if (vcpu) {
        InterlockedExchange(&vcpu->NativeTeardownRejectMask,
                            static_cast<LONG>(rejectMask));
    }
    if (authenticatedUnload && descriptorContractSafe && noPendingEvent &&
        guestStateValid) {
        c->AbortVm = 1;
        c->HaltVm = 0;
    } else if (c) {
        c->AbortVm = 0;
        c->HaltVm = 1;
    }
}

// VMRESUME can fail after the normal epilogue has restored the guest register
// set but before hardware re-enters non-root mode.  Return through the native
// teardown path only when the saved context passes the same conservative checks
// used by HvRestoreStateAndReturn; otherwise retain the quarantine path.
extern "C" ULONG HandleVmResumeFailure(GuestContext* c, u64 resumeFlags) {
    const u32 id = CurrentProcessorIndex();
    VcpuContext* vcpu =
        g_VcpuData && id < g_ProcessorCount ? &g_VcpuData[id] : nullptr;
    const bool vmFailValid = (resumeFlags & (1ULL << 6)) != 0;
    if (vcpu) {
        vcpu->LastVmResumeFlags = resumeFlags;
        vcpu->LastVmInstructionRflags = resumeFlags;
        WriteHvTrace(vcpu, id, HvTraceEventVmresumeFail, resumeFlags);
        vcpu->LastVmInstructionError = 0;
        ClearVmcsDiagnosticValidity(vcpu,
                                    HvVmcsValidityVmInstructionError);
        // VMfailValid (ZF=1) makes VM_INSTRUCTION_ERROR architecturally
        // available. VMfailInvalid (CF=1) does not, so never issue a VMREAD
        // for that case.
        if (vmFailValid) {
            if (!VmReadChecked(VM_INSTRUCTION_ERROR,
                               &vcpu->LastVmInstructionError)) {
                vcpu->LastExitAction = kExitActionHalt;
                FailFirstExitProbeAtFatalBoundary(vcpu, id);
                if (c) {
                    c->AbortVm = 0;
                    c->HaltVm = 1;
                }
                HvCaptureFatalSnapshotPreVmxoff(c);
                return 0;
            }
            SetVmcsDiagnosticValidity(vcpu,
                                      HvVmcsValidityVmInstructionError);
        }
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, id);
    }
    const bool xssPreservationValid = !g_XsavesEnabled ||
        (c && (c->GuestXss & ~g_XsavesMask) == 0);
    if (c && vcpu && !xssPreservationValid) {
        WriteHvTrace(vcpu, id, HvTraceEventXssPreservationFail,
                     c->GuestXss, g_XsavesMask,
                     g_GuestXssWriteMask, g_HostXssMask);
    }
    if (c) {
        c->AbortVm = 0;
        c->HaltVm = 1;
    }
    // A failed VMRESUME is never a proven native continuation. Freeze the
    // first VMCS image while VMX is still active and let the assembly fatal
    // path leave VMX without manufacturing an IRETQ return.
    HvCaptureFatalSnapshotPreVmxoff(c);
    return 0;
}

static void ReleaseHvCrashBlob() {
    const LONG lifecycle =
        InterlockedCompareExchange(&g_HvLifecycle, 0, 0);
    const bool deregisteredOwner =
        InterlockedCompareExchange(&g_HvCrashBlobReleaseAuthorized, 0, 0) != 0;
    // A registered callback may still publish this buffer at bugcheck time.
    // Quarantine likewise retains every diagnostic allocation used by a live
    // or parked VCPU. A never-registered startup failure may free only after
    // the lifecycle has completed its transition back to Idle.
    if (g_HvBugCheckReasonRegistered ||
        lifecycle == kHvLifecycleQuarantined ||
        (!deregisteredOwner && lifecycle != kHvLifecycleIdle)) {
        return;
    }
    if (!g_HvCrashBlob) {
        InterlockedExchange(&g_HvCrashBlobReleaseAuthorized, 0);
        return;
    }
    ExFreePoolWithTag(g_HvCrashBlob, TAG_HVCB);
    g_HvCrashBlob = nullptr;
    g_HvCrashBlobSize = 0;
    InterlockedExchange(&g_HvCrashBlobCaptured, HvCrashBlobCaptureIdle);
    InterlockedExchange(&g_HvCrashBlobReleaseAuthorized, 0);
}

static bool InitializeHvCrashBlob(u32 cpuCount) {
    if (cpuCount == 0) {
        return false;
    }

    const SIZE_T snapshotCount = static_cast<SIZE_T>(cpuCount);
    const SIZE_T size = offsetof(HvCrashBlob, CpuSnapshots) +
                        snapshotCount * sizeof(HvFatalSnapshot) +
                        snapshotCount * HV_TRACE_TAIL_RECORDS *
                            sizeof(HvTraceRecord);

    if (g_HvCrashBlob && g_HvCrashBlobSize == size) {
        InterlockedExchange(&g_HvCrashBlobCaptured, HvCrashBlobCaptureIdle);
        RtlZeroMemory(g_HvCrashBlob, size);
        g_HvCrashBlob->Signature = kHvCrashBlobSignature;
        g_HvCrashBlob->Version = kHvCrashBlobVersion;
        g_HvCrashBlob->CpuCount = static_cast<u32>(snapshotCount);
        g_HvCrashBlob->TraceRecordsPerCpu = HV_TRACE_TAIL_RECORDS;
        g_HvCrashBlob->BuildId = kHvBuildId;
        g_HvCrashBlob->ContractId = g_VmxCapabilityProfile;
        return true;
    }

    // Never replace callback storage whose ownership did not complete a full
    // deregistration/Idle transition. Losing the old pointer would make a
    // later bugcheck callback dereference freed or unreachable evidence.
    if (g_HvCrashBlob) return false;

    void* memory = ExAllocatePoolWithTag(NonPagedPoolNx, size, TAG_HVCB);
    if (!memory) return false;

    g_HvCrashBlob = static_cast<HvCrashBlob*>(memory);
    g_HvCrashBlobSize = size;
    InterlockedExchange(&g_HvCrashBlobCaptured, HvCrashBlobCaptureIdle);
    RtlZeroMemory(g_HvCrashBlob, size);
    g_HvCrashBlob->Signature = kHvCrashBlobSignature;
    g_HvCrashBlob->Version = kHvCrashBlobVersion;
    g_HvCrashBlob->CpuCount = static_cast<u32>(snapshotCount);
    g_HvCrashBlob->TraceRecordsPerCpu = HV_TRACE_TAIL_RECORDS;
    g_HvCrashBlob->BuildId = kHvBuildId;
    g_HvCrashBlob->ContractId = g_VmxCapabilityProfile;
    g_HvCrashBlob->BugcheckCode = 0;
    g_HvCrashBlob->BugcheckArg1 = 0;
    g_HvCrashBlob->BugcheckArg2 = 0;
    g_HvCrashBlob->BugcheckArg3 = 0;
    g_HvCrashBlob->BugcheckArg4 = 0;
    g_HvCrashBlob->Reserved = 0;
    return true;
}

static void CaptureHvCrashBlob(ULONG_PTR bugcheckCode,
                              ULONG_PTR bugcheckParam1,
                              ULONG_PTR bugcheckParam2,
                              ULONG_PTR bugcheckParam3,
                              ULONG_PTR bugcheckParam4) {
    if (!g_HvCrashBlob) return;

    const u32 maxSnapshots = g_HvCrashBlob->CpuCount;
    const u32 snapshotCount = g_ProcessorCount < maxSnapshots ? g_ProcessorCount : maxSnapshots;
    HvCrashBlob* blob = g_HvCrashBlob;
    HvFatalSnapshot* snapshots = blob->CpuSnapshots;

    RtlZeroMemory(blob, g_HvCrashBlobSize);
    blob->Signature = kHvCrashBlobSignature;
    blob->Version = kHvCrashBlobVersion;
    blob->CpuCount = maxSnapshots;
    blob->SnapshotCount = snapshotCount;
    blob->TraceRecordsPerCpu = HV_TRACE_TAIL_RECORDS;
    blob->Lifecycle = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLifecycle, 0, 0));
    blob->BuildId = kHvBuildId;
    blob->ContractId = g_VmxCapabilityProfile;
    blob->BugcheckCode = bugcheckCode;
    blob->BugcheckArg1 = bugcheckParam1;
    blob->BugcheckArg2 = bugcheckParam2;
    blob->BugcheckArg3 = bugcheckParam3;
    blob->BugcheckArg4 = bugcheckParam4;
    blob->Reserved = g_HvImagePinned != 0 ? 1U : 0U;
    blob->LaunchTelemetrySignature = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchTelemetrySignature, 0, 0));
    blob->LaunchExpectedProcessors = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchExpectedProcessors, 0, 0));
    blob->LaunchProbeEntered = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchProbeEntered, 0, 0));
    blob->LaunchProbeCompleted = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchProbeCompleted, 0, 0));
    blob->LaunchDispatchEntered = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchDispatchEntered, 0, 0));
    blob->LaunchAssemblyEntered = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchAssemblyEntered, 0, 0));
    blob->LaunchPrepareEntered = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchPrepareEntered, 0, 0));
    blob->LaunchPrepareSucceeded = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchPrepareSucceeded, 0, 0));
    blob->LaunchGuestEntered = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchGuestEntered, 0, 0));
    blob->LaunchVmlaunchIssued = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchVmlaunchIssued, 0, 0));
    blob->LaunchVmlaunchReturned = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchVmlaunchReturned, 0, 0));
    blob->LaunchGuestStarted = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchGuestStarted, 0, 0));
    blob->LaunchMarkedLaunched = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchMarkedLaunched, 0, 0));
    blob->LaunchVmExitAsmReached = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchVmExitAsmReached, 0, 0));
    blob->LaunchFirstVmExitEntered = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchFirstVmExitEntered, 0, 0));
    blob->LaunchDispatchReturned = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchDispatchReturned, 0, 0));
    blob->LaunchLastProbeProcessor = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchLastProbeProcessor, 0, 0));
    blob->LaunchLastDispatchProcessor = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchLastDispatchProcessor, 0, 0));
    blob->LaunchLastPrepareProcessor = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchLastPrepareProcessor, 0, 0));
    blob->LaunchLastReturnProcessor = static_cast<u32>(
        InterlockedCompareExchange(&g_HvLaunchLastReturnProcessor, 0, 0));
    RtlCopyMemory(&blob->HostFault, &g_HvHostFaultRecord,
                  sizeof(blob->HostFault));
    const u64 vmxOffFailureFlags = static_cast<u64>(
        InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&g_HvVmxOffFailureFlagsAsm),
            0, 0));

    for (u32 i = 0; i < snapshotCount; ++i) {
        HvFatalSnapshot& out = snapshots[i];
        out.Cpu = i;
        out.Lifecycle = static_cast<u32>(
            InterlockedCompareExchange(&g_HvLifecycle, 0, 0));
        out.LaunchStage = 0;
        out.VmInstructionError = 0;
        out.VmExitCount = 0;
        out.VmcsSetupPhase = 0;
        out.VmcsCurrentState = VmcsCurrentStateNone;
        out.FirstExitProbeState = 0;
        out.FirstExitProbeBaselineVmExits = 0;
        out.FirstExitProbeBaselineVmResumes = 0;
        out.FirstExitProbeObservedVmExits = 0;
        out.FirstExitProbeObservedVmResumes = 0;
        out.FirstExitProbeReason = 0;
        out.FirstExitProbeAction = 0;
        out.FatalSnapshotCommitState = 0;
        out.LaunchFlags = 0;
        out.FirstExitProbeResumeFlags = 0;
        out.ExitReasonRaw = 0;
        out.ExitMsrIndex = 0;
        out.ExitMsrValue = 0;
        out.ExitQualification = 0;
        out.GuestRip = 0;
        out.GuestRsp = 0;
        out.GuestRflags = 0;
        out.GuestCr0 = 0;
        out.GuestCr3 = 0;
        out.GuestCr4 = 0;
        out.GuestCr2 = 0;
        out.LaunchRawGuestCr3 = 0;
        out.LaunchGuestCr3 = 0;
        out.LaunchRawHostCr3 = 0;
        out.LaunchHostCr3 = 0;
        out.LaunchCr3Metadata = 0;
        out.GuestInterruptibility = 0;
        out.GuestActivity = 0;
        out.EntryIntrInfo = 0;
        out.EntryIntrError = 0;
        out.EntryInstructionLength = 0;
        out.ExitIntrInfo = 0;
        out.ExitIntrError = 0;
        out.IdtVectoringInfo = 0;
        out.IdtVectoringError = 0;
        out.GuestXcr0 = 0;
        out.GuestXss = 0;
        out.GuestEfer = 0;
        out.GuestPat = 0;
        out.GuestDebugctl = 0;
        out.GuestSCet = 0;
        out.GuestSsp = 0;
        out.GuestInterruptSspTable = 0;
        out.GuestPtCtl = 0;
        out.VmInstructionRflags = 0;
        out.NativeTeardownRejectMask = 0;
        out.VmcsReadFailed = 0;
        out.VmcsValueMismatch = 0;
        out.VmcsFailureCommitState = 0;
        out.VmcsFailureReason = 0;
        out.VmcsFailureArg0 = 0;
        out.VmcsFailureArg1 = 0;
        out.DiagnosticValidity = 0;
        out.FirstVmcsReadField = 0;
        out.FirstVmcsReadFlags = 0;
        out.FirstVmcsReadError = 0;
        out.FirstVmcsMismatchField = 0;
        out.FirstVmcsMismatchExpected = 0;
        out.FirstVmcsMismatchActual = 0;
        out.FirstVmcsMismatchMask = 0;
        out.FirstVmcsWriteField = 0;
        out.FirstVmcsWriteFlags = 0;
        out.FirstVmcsWriteError = 0;
        out.VmxOffFailureFlags = 0;
        out.LaunchDescriptorRejectMask = 0;
        out.XsetbvExitCount = 0;
        out.XssWriteExitCount = 0;
        out.XssWriteRejectCount = 0;
        out.LaunchDescriptorSelectorsLow = 0;
        out.LaunchDescriptorSelectorsHigh = 0;
        out.LaunchDescriptorGdtBase = 0;
        out.LaunchDescriptorIdtBase = 0;
        out.LaunchDescriptorTssBase = 0;
        out.LastXsetbvPrevious = 0;
        out.LastXsetbvRequested = 0;
        out.LastXssWritePrevious = 0;
        out.LastXssWriteRequested = 0;

        if (g_VcpuData && i < g_ProcessorCount) {
            const VcpuContext& vcpu = g_VcpuData[i];
            out.Lifecycle = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&vcpu.State), 0, 0));
            out.LaunchStage = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&vcpu.LaunchStage), 0, 0));
            out.VmInstructionError = static_cast<u32>(vcpu.LastVmInstructionError);
            out.VmExitCount = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&vcpu.VmExitCount), 0, 0));
            out.VmcsSetupPhase = static_cast<u32>(vcpu.VmcsSetupPhase);
            out.VmcsCurrentState = static_cast<u32>(InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.VmcsCurrent), 0, 0));
            const long fatalSnapshotCommitState =
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(
                        &vcpu.FatalSnapshotCommitState),
                    0, 0);
            out.FatalSnapshotCommitState =
                static_cast<u32>(fatalSnapshotCommitState);
            out.FirstExitProbeState = static_cast<u32>(
                ReadFirstExitProbeState(&vcpu));
            out.FirstExitProbeBaselineVmExits = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(
                        &vcpu.FirstExitProbeBaselineVmExits), 0, 0));
            out.FirstExitProbeBaselineVmResumes = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(
                        &vcpu.FirstExitProbeBaselineVmResumes), 0, 0));
            out.FirstExitProbeObservedVmExits = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(
                        &vcpu.FirstExitProbeObservedVmExits), 0, 0));
            out.FirstExitProbeObservedVmResumes = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(
                        &vcpu.FirstExitProbeObservedVmResumes), 0, 0));
            out.FirstExitProbeReason = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&vcpu.FirstExitProbeReason),
                    0, 0));
            out.FirstExitProbeAction = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&vcpu.FirstExitProbeAction),
                    0, 0));
            out.LaunchFlags = vcpu.LastLaunchFlags;
            out.FirstExitProbeResumeFlags = static_cast<u64>(
                InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(
                        const_cast<u64*>(&vcpu.FirstExitProbeResumeFlags)),
                    0, 0));
            out.ExitReasonRaw = vcpu.LastExitReasonRaw;
            out.ExitMsrIndex = vcpu.LastExitMsrIndex;
            out.ExitMsrValue = vcpu.LastExitMsrValue;
            out.ExitQualification = vcpu.LastExitQualification;
            out.GuestRip = vcpu.LastGuestRip;
            out.GuestRsp = vcpu.LastGuestRsp;
            out.GuestRflags = vcpu.LastRflags;
            out.GuestCr0 = vcpu.LastGuestCr0;
            out.GuestCr3 = vcpu.LastGuestCr3;
            out.GuestCr4 = vcpu.LastGuestCr4;
            out.GuestCr2 = vcpu.LastGuestCr2;
            out.LaunchRawGuestCr3 =
                ReadLaunchCr3Field(&vcpu.LaunchRawGuestCr3);
            out.LaunchGuestCr3 = ReadLaunchCr3Field(&vcpu.LaunchGuestCr3);
            out.LaunchRawHostCr3 =
                ReadLaunchCr3Field(&vcpu.LaunchRawHostCr3);
            out.LaunchHostCr3 = ReadLaunchCr3Field(&vcpu.LaunchHostCr3);
            out.LaunchCr3Metadata =
                ReadLaunchCr3Field(&vcpu.LaunchCr3Metadata);
            out.GuestInterruptibility = vcpu.LastGuestInterruptibility;
            out.GuestActivity = vcpu.LastGuestActivity;
            out.EntryIntrInfo = vcpu.LastVmEntryIntrInfo;
            out.EntryIntrError = vcpu.LastVmEntryIntrError;
            out.EntryInstructionLength = vcpu.LastVmEntryInstructionLength;
            out.ExitIntrInfo = vcpu.LastVmExitIntrInfo;
            out.ExitIntrError = vcpu.LastVmExitIntrError;
            out.IdtVectoringInfo = vcpu.LastIdtVectoringInfo;
            out.IdtVectoringError = vcpu.LastIdtVectoringError;
            out.GuestXcr0 = vcpu.LastGuestXcr0;
            out.GuestXss = vcpu.LastGuestXss;
            out.GuestEfer = vcpu.LastGuestEfer;
            out.GuestPat = vcpu.LastGuestPat;
            out.GuestDebugctl = vcpu.LastGuestDebugctl;
            out.GuestSCet = vcpu.LastGuestSCet;
            out.GuestSsp = vcpu.LastGuestSsp;
            out.GuestInterruptSspTable = vcpu.LastGuestInterruptSspTable;
            out.GuestPtCtl = vcpu.LastPtCtl;
            out.VmInstructionRflags = vcpu.LastVmInstructionRflags;
            out.NativeTeardownRejectMask = ReadNativeTeardownRejectMask(&vcpu);
            out.VmcsReadFailed = static_cast<u32>(InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.VmcsReadFailed), 0, 0));
            out.VmcsValueMismatch = static_cast<u32>(InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.VmcsValueMismatch), 0, 0));
            ReadVmcsFailureRecord(&vcpu, &out.VmcsFailureCommitState,
                                  &out.VmcsFailureReason,
                                  &out.VmcsFailureArg0,
                                  &out.VmcsFailureArg1);
            out.LaunchDescriptorRejectMask = static_cast<u32>(
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(&vcpu.LaunchDescriptorRejectMask),
                    0, 0));
            out.XsetbvExitCount = static_cast<u32>(InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.XsetbvExitCount), 0, 0));
            out.XssWriteExitCount = static_cast<u32>(InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.XssWriteExitCount), 0, 0));
            out.XssWriteRejectCount = static_cast<u32>(InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.XssWriteRejectCount), 0, 0));
            out.LaunchDescriptorSelectorsLow = vcpu.LaunchDescriptorSelectorsLow;
            out.LaunchDescriptorSelectorsHigh = vcpu.LaunchDescriptorSelectorsHigh;
            out.LaunchDescriptorGdtBase = vcpu.LaunchDescriptorGdtBase;
            out.LaunchDescriptorIdtBase = vcpu.LaunchDescriptorIdtBase;
            out.LaunchDescriptorTssBase = vcpu.LaunchDescriptorTssBase;
            out.LastXsetbvPrevious = vcpu.LastXsetbvPrevious;
            out.LastXsetbvRequested = vcpu.LastXsetbvRequested;
            out.LastXssWritePrevious = vcpu.LastXssWritePrevious;
            out.LastXssWriteRequested = vcpu.LastXssWriteRequested;
            out.DiagnosticValidity = ReadVmcsDiagnosticValidity(&vcpu);
            out.FirstVmcsReadField = vcpu.FirstVmcsReadField;
            out.FirstVmcsReadFlags = vcpu.FirstVmcsReadFlags;
            out.FirstVmcsReadError = vcpu.FirstVmcsReadError;
            out.FirstVmcsMismatchField = vcpu.FirstVmcsMismatchField;
            out.FirstVmcsMismatchExpected = vcpu.FirstVmcsMismatchExpected;
            out.FirstVmcsMismatchActual = vcpu.FirstVmcsMismatchActual;
            out.FirstVmcsMismatchMask = vcpu.FirstVmcsMismatchMask;
            out.FirstVmcsWriteField = vcpu.FirstVmcsWriteField;
            out.FirstVmcsWriteFlags = vcpu.FirstVmcsWriteFlags;
            out.FirstVmcsWriteError = vcpu.FirstVmcsWriteError;
            MemoryBarrier();
            const long finalFatalSnapshotCommitState =
                InterlockedCompareExchange(
                    const_cast<volatile LONG*>(
                        &vcpu.FatalSnapshotCommitState),
                    0, 0);
            if (fatalSnapshotCommitState != HvFatalSnapshotCommitted ||
                finalFatalSnapshotCommitState != HvFatalSnapshotCommitted ||
                finalFatalSnapshotCommitState != fatalSnapshotCommitState) {
                // an uncommitted or changing snapshot is not coherent, so
                // expose the post-copy state and reject its validity mask
                out.FatalSnapshotCommitState = static_cast<u32>(
                    finalFatalSnapshotCommitState);
                out.DiagnosticValidity = 0;
            }
        }
        if (g_VcpuData && i < g_ProcessorCount) {
            out.VmcsClearFlags = g_VcpuData[i].LastVmclearFlags;
        } else {
            out.VmcsClearFlags = 0;
        }
        out.VmxOffFailureFlags = vmxOffFailureFlags;
    }

    auto* traceTail = reinterpret_cast<HvTraceRecord*>(
        reinterpret_cast<UCHAR*>(snapshots) +
        snapshotCount * sizeof(HvFatalSnapshot));
    RtlZeroMemory(traceTail, snapshotCount * HV_TRACE_TAIL_RECORDS *
                                sizeof(HvTraceRecord));
    for (u32 i = 0; i < snapshotCount; ++i) {
        if (!g_VcpuData || i >= g_ProcessorCount ||
            !g_VcpuData[i].TraceRing || g_VcpuData[i].TraceCapacity == 0) {
            continue;
        }
        VcpuContext& vcpu = g_VcpuData[i];
        const u64 writeIndex = static_cast<u64>(
            InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(
                                              &vcpu.TraceWriteIndex),
                                          0, 0));
        const u64 available = writeIndex < vcpu.TraceCapacity
                                  ? writeIndex
                                  : vcpu.TraceCapacity;
        const u64 count = available < HV_TRACE_TAIL_RECORDS
                              ? available
                              : HV_TRACE_TAIL_RECORDS;
        for (u64 j = 0; j < count; ++j) {
            const u64 sequence = writeIndex - count + j;
            const u32 slot = static_cast<u32>(sequence % vcpu.TraceCapacity);
            const HvTraceRecord record = vcpu.TraceRing[slot];
            if (record.Sequence == sequence) {
                traceTail[static_cast<SIZE_T>(i) * HV_TRACE_TAIL_RECORDS + j] =
                    record;
            }
        }
    }

    MemoryBarrier();
}

extern "C" VOID HvSecondaryDumpDataCallback(
    KBUGCHECK_CALLBACK_REASON Reason,
    PKBUGCHECK_REASON_CALLBACK_RECORD Record,
    PVOID ReasonSpecificData,
    ULONG ReasonSpecificDataLength) {
    UNREFERENCED_PARAMETER(Record);
    if (Reason != KbCallbackSecondaryMultiPartDumpData) return;

    if (!ReasonSpecificData ||
        ReasonSpecificDataLength < sizeof(KBUGCHECK_SECONDARY_DUMP_DATA_EX)) {
        return;
    }

    PKBUGCHECK_SECONDARY_DUMP_DATA_EX dumpData =
        static_cast<PKBUGCHECK_SECONDARY_DUMP_DATA_EX>(ReasonSpecificData);
    const LONG captureState = InterlockedCompareExchange(
        &g_HvCrashBlobCaptured, HvCrashBlobCaptureWriting,
        HvCrashBlobCaptureIdle);
    if (captureState == HvCrashBlobCaptureIdle) {
        CaptureHvCrashBlob(dumpData->BugCheckCode,
                           dumpData->BugCheckParameter1,
                           dumpData->BugCheckParameter2,
                           dumpData->BugCheckParameter3,
                           dumpData->BugCheckParameter4);
        MemoryBarrier();
        InterlockedExchange(&g_HvCrashBlobCaptured,
                            HvCrashBlobCaptureCommitted);
    } else if (captureState == HvCrashBlobCaptureWriting) {
        dumpData->Guid = kHvCrashBlobGuid;
        dumpData->OutBuffer = nullptr;
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    } else if (captureState != HvCrashBlobCaptureCommitted) {
        // A corrupted state must never be treated as a committed blob. Keep
        // the callback answer empty so dump code cannot copy stale memory.
        dumpData->Guid = kHvCrashBlobGuid;
        dumpData->OutBuffer = nullptr;
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    }
    dumpData->Guid = kHvCrashBlobGuid;
    const UCHAR* base = reinterpret_cast<const UCHAR*>(g_HvCrashBlob);
    const SIZE_T cursor = reinterpret_cast<SIZE_T>(dumpData->Context);

    if (!g_HvCrashBlob || g_HvCrashBlobSize == 0) {
        dumpData->OutBuffer = nullptr;
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    }

    if (cursor >= g_HvCrashBlobSize) {
        dumpData->OutBuffer = const_cast<UCHAR*>(base + g_HvCrashBlobSize);
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    }

    const ULONG maxAllowed = dumpData->MaximumAllowed;
    const ULONG remaining = static_cast<ULONG>(
        g_HvCrashBlobSize - cursor < static_cast<SIZE_T>(MAXULONG) ?
        g_HvCrashBlobSize - cursor : MAXULONG);
    if (maxAllowed == 0 && remaining != 0) {
        // Returning ADDITIONAL_DATA with an unchanged context would make the
        // dump writer request the same chunk forever. Report no data and end
        // this callback transaction instead.
        dumpData->OutBuffer = nullptr;
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    }
    const ULONG copyLength = (maxAllowed >= remaining) ? remaining : maxAllowed;
    dumpData->OutBuffer = const_cast<UCHAR*>(base + cursor);
    dumpData->OutBufferLength = copyLength;
    dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
    if (copyLength < remaining) {
        dumpData->Flags |= KB_SECONDARY_DATA_FLAG_ADDITIONAL_DATA;
        dumpData->Context = reinterpret_cast<PVOID>(cursor + copyLength);
    } else {
        dumpData->Context = nullptr;
    }
}

bool RegisterSecondaryDumpCallback() {
    if (g_HvBugCheckReasonRegistered) return true;

    const BOOLEAN ok = KeRegisterBugCheckReasonCallback(
        &g_HvBugCheckReasonRecord,
        HvSecondaryDumpDataCallback,
        KbCallbackSecondaryMultiPartDumpData,
        reinterpret_cast<PUCHAR>(const_cast<char*>(kHvCrashBlobComponent)));
    if (!ok) return false;

    g_HvBugCheckReasonRegistered = true;
    return true;
}

void UnregisterSecondaryDumpCallback() {
    if (!g_HvBugCheckReasonRegistered) {
        ReleaseHvCrashBlob();
        return;
    }

    if (InterlockedCompareExchange(&g_HvLifecycle, 0, 0) ==
        kHvLifecycleQuarantined) {
        return;
    }
    if (!KeDeregisterBugCheckReasonCallback(&g_HvBugCheckReasonRecord)) {
        // Returning would let later teardown free callback-owned nonpaged
        // storage. Keep ownership intact and use the driver's bugcheck code.
        KeBugCheckEx(kHvFatalBugCheck,
                     0xCB01,
                     reinterpret_cast<ULONG_PTR>(&g_HvBugCheckReasonRecord),
                     reinterpret_cast<ULONG_PTR>(g_HvCrashBlob),
                     static_cast<ULONG_PTR>(g_HvCrashBlobSize));
        __assume(0);
    }
    g_HvBugCheckReasonRegistered = false;
    InterlockedExchange(&g_HvCrashBlobReleaseAuthorized, 1);
    ReleaseHvCrashBlob();
}

// Capture the VMCS while VMX is still active. The fatal assembly path calls
// this before VMXOFF; after VMXOFF only the software copy is trustworthy.
extern "C" void HvCaptureFatalSnapshotPreVmxoff(GuestContext* c) {
    if (!g_VcpuData) return;
    const u32 cpu = CurrentProcessorIndex();
    if (cpu >= g_ProcessorCount) return;

    VcpuContext* vcpu = &g_VcpuData[cpu];
    if (InterlockedCompareExchange(&vcpu->FatalSnapshotCommitState,
                                   HvFatalSnapshotWriting,
                                   HvFatalSnapshotEmpty) !=
        HvFatalSnapshotEmpty) {
        return;
    }
    const u64 vmxOffFailureFlags = static_cast<u64>(
        InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&g_HvVmxOffFailureFlagsAsm),
            0, 0));
    if (vmxOffFailureFlags != 0) {
        vcpu->LastVmInstructionRflags = vmxOffFailureFlags;
    }
    const u64 priorValidity = ReadVmcsDiagnosticValidity(vcpu);
    const bool priorEntryFailure = vcpu->LastExitEntryFailure != 0;
    // VMRESUME returns in VMX root without creating a new VM-exit record. The
    // VMCS exit fields are therefore only a last-known image at that boundary.
    // Keep the immediate VMfailValid error, but invalidate the old exit image.
    const bool resumeFailureBoundary = vcpu->LastVmResumeFlags != 0;
    constexpr u64 kTransientSnapshotValidity =
        HvVmcsValidityExitReason | HvVmcsValidityExitQualification |
        HvVmcsValidityExitInstructionLength | HvVmcsValidityEventState |
        HvVmcsValidityGuestState;
    const u64 preservedValidity =
        (resumeFailureBoundary || priorEntryFailure)
            ? priorValidity & HvVmcsValidityVmInstructionError
            : priorValidity & ~kTransientSnapshotValidity;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(
                              &vcpu->VmcsDiagnosticValidity),
                          static_cast<LONG64>(preservedValidity));
    if ((preservedValidity & HvVmcsValidityVmInstructionError) == 0) {
        vcpu->LastVmInstructionError = 0;
    }
    u64 value = 0;
    bool entryFailure = false;
    bool reasonValid = false;
    // A VMRESUME failure has no current VM-exit information. Do not turn the
    // preceding exit reason or qualification into false evidence.
    if (!resumeFailureBoundary && VmReadChecked(VM_EXIT_REASON, &value)) {
        reasonValid = true;
        vcpu->LastExitReasonRaw = static_cast<u32>(value);
        vcpu->LastExitReasonBasic = static_cast<u32>(value) & 0xFFFFU;
        entryFailure = (static_cast<u32>(value) & 0x80000000U) != 0;
        vcpu->LastExitEntryFailure = entryFailure ? 1U : 0U;
        if (!entryFailure) {
            // VM_INSTRUCTION_ERROR belongs to an immediate VMfailValid, not
            // to a later ordinary VM-exit transaction
            ClearVmcsDiagnosticValidity(vcpu,
                                        HvVmcsValidityVmInstructionError);
        }
        if (c && (vcpu->LastExitReasonBasic == VM_EXIT_REASON_RDMSR ||
                  vcpu->LastExitReasonBasic == VM_EXIT_REASON_WRMSR)) {
            vcpu->LastExitMsrIndex = static_cast<u32>(c->Rcx);
            vcpu->LastExitMsrValue =
                static_cast<u64>(static_cast<u32>(c->Rax)) |
                (static_cast<u64>(static_cast<u32>(c->Rdx)) << 32);
        }
        SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityExitReason);
    } else {
        // A failed reason read leaves all exit metadata unknown. Keep the raw
        // storage for postmortem comparison, but make its validity explicit.
        vcpu->LastExitEntryFailure = 0;
        ClearVmcsDiagnosticValidity(
            vcpu, HvVmcsValidityExitReason |
                      HvVmcsValidityExitQualification |
                      HvVmcsValidityExitInstructionLength |
                      HvVmcsValidityEventState | HvVmcsValidityGuestState);
    }

    const bool qualificationDefined =
        reasonValid && IsVmEntryFailureQualificationDefined(
                           static_cast<u32>(vcpu->LastExitReasonRaw));
    if (qualificationDefined &&
        VmReadChecked(EXIT_QUALIFICATION, &value)) {
        vcpu->LastExitQualification = value;
        SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityExitQualification);
    } else {
        ClearVmcsDiagnosticValidity(vcpu,
                                    HvVmcsValidityExitQualification);
    }

    if (!reasonValid || resumeFailureBoundary || entryFailure) {
        // Intel leaves guest-state and event fields unmodified for this exit.
        // Keep their previous values only as raw storage, never as evidence.
        InterlockedExchange(&vcpu->LastEventSnapshotValid, 0);
        goto fatalSnapshotCommit;
    }
    if (VmReadChecked(GUEST_RIP, &value)) vcpu->LastGuestRip = value;
    if (VmReadChecked(GUEST_RSP, &value)) vcpu->LastGuestRsp = value;
    if (VmReadChecked(GUEST_RFLAGS, &value)) vcpu->LastRflags = value;
    if (VmReadChecked(GUEST_CR0, &value)) vcpu->LastGuestCr0 = value;
    if (VmReadChecked(GUEST_CR3, &value)) vcpu->LastGuestCr3 = value;
    if (VmReadChecked(GUEST_CR4, &value)) vcpu->LastGuestCr4 = value;
    if (VmReadChecked(GUEST_INTERRUPTIBILITY_INFO, &value)) {
        vcpu->LastGuestInterruptibility = static_cast<u32>(value);
    }
    if (VmReadChecked(GUEST_ACTIVITY_STATE, &value)) {
        vcpu->LastGuestActivity = static_cast<u32>(value);
    }
    if (VmReadChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, &value)) {
        vcpu->LastVmEntryIntrInfo = static_cast<u32>(value);
    }
    if (VmReadChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, &value)) {
        vcpu->LastVmEntryIntrError = static_cast<u32>(value);
    }
    if (VmReadChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, &value)) {
        vcpu->LastVmEntryInstructionLength = static_cast<u32>(value);
    }
    if (VmReadChecked(VM_EXIT_INTR_INFO, &value)) {
        vcpu->LastVmExitIntrInfo = static_cast<u32>(value);
    }
    if (VmReadChecked(VM_EXIT_INTR_ERROR_CODE, &value)) {
        vcpu->LastVmExitIntrError = static_cast<u32>(value);
    }
    if (VmReadChecked(VM_EXIT_IDT_VECTORING_INFO, &value)) {
        vcpu->LastIdtVectoringInfo = static_cast<u32>(value);
    }
    if (VmReadChecked(VM_EXIT_IDT_VECTORING_ERROR_CODE, &value)) {
        vcpu->LastIdtVectoringError = static_cast<u32>(value);
    }
    if (VmReadChecked(GUEST_EFER, &value)) vcpu->LastGuestEfer = value;
    if (VmReadChecked(GUEST_PAT, &value)) vcpu->LastGuestPat = value;
    if (VmReadChecked(GUEST_DEBUGCTL, &value)) {
        vcpu->LastGuestDebugctl = value;
    }
    if (g_CetVmcsEnabled) {
        if (VmReadChecked(GUEST_S_CET, &value)) vcpu->LastGuestSCet = value;
        if (VmReadChecked(GUEST_SSP, &value)) vcpu->LastGuestSsp = value;
        if (VmReadChecked(GUEST_INTR_SSP_TABLE, &value)) {
            vcpu->LastGuestInterruptSspTable = value;
        }
    }
    if (c) {
        vcpu->LastGuestXcr0 = c->GuestXcr0;
        vcpu->LastGuestXss = c->GuestXss;
    }
fatalSnapshotCommit:
    // LastPtCtl is sampled during the owning CPU's passive-level launch
    // preparation. Do not issue RDMSR here: older Intel processors may not
    // implement the PT MSR window, and this callback runs at HIGH_LEVEL.
    WriteHvTrace(vcpu, cpu, HvTraceEventFatalSnapshot,
                 vcpu->LastExitReasonRaw, vcpu->LastVmInstructionError,
                 vcpu->LastGuestRip, vcpu->LastGuestRsp);
    MemoryBarrier();
    InterlockedExchange(&vcpu->FatalSnapshotCommitState,
                        HvFatalSnapshotCommitted);
}

// A frame that cannot pass native teardown validation has no safe instruction
// pointer or stack. Fail fast with a debugger-visible dump instead of waiting
// for CLOCK_WATCHDOG_TIMEOUT to obscure the original VMX failure.
extern "C" __declspec(noreturn) void HvFatalBugCheck(GuestContext* c) {
    // VMXOFF may have invalidated the transition frame.  Do not dereference it
    // or call the trace path here; the pre-VMXOFF snapshot is the only trusted
    // source for bugcheck parameters after the processor leaves VMX operation.
    (void)c;
    const ULONG_PTR cpu = CurrentProcessorIndex();
    ULONG_PTR reason = 0;
    ULONG_PTR rip = 0;
    ULONG_PTR rsp = 0;
    if (g_VcpuData && cpu < g_ProcessorCount) {
        const VcpuContext& vcpu = g_VcpuData[cpu];
        const u64 validity = ReadVmcsDiagnosticValidity(&vcpu);
        if ((validity & HvVmcsValidityExitReason) != 0) {
            reason = static_cast<ULONG_PTR>(vcpu.LastExitReasonRaw);
        }
        if ((validity & HvVmcsValidityGuestState) != 0) {
            rip = static_cast<ULONG_PTR>(vcpu.LastGuestRip);
            rsp = static_cast<ULONG_PTR>(vcpu.LastGuestRsp);
        }
    }
    MemoryBarrier();
    KeBugCheckEx(kHvFatalBugCheck, cpu, reason, rip, rsp);
    __assume(0);
}

extern "C" __declspec(noreturn) void HvHostExceptionBugCheck() {
    // The assembly stub has already committed the architectural prefix using
    // only flat-address writes. Everything below is best-effort enrichment;
    // even a recursive fault leaves the first vector/RIP/CR2 tuple intact.
    const u32 cpu = CurrentProcessorIndex();
    g_HvHostFaultRecord.Cpu = cpu;

    if (g_VcpuData && cpu < g_ProcessorCount) {
        const VcpuContext& vcpu = g_VcpuData[cpu];
        g_HvHostFaultRecord.LastExitReasonRaw = vcpu.LastExitReasonRaw;
        g_HvHostFaultRecord.LastGuestRip = vcpu.LastGuestRip;
        g_HvHostFaultRecord.LastGuestRsp = vcpu.LastGuestRsp;
        g_HvHostFaultRecord.LastExitQualification = vcpu.LastExitQualification;
        g_HvHostFaultRecord.LastIdtVectoringInfo = vcpu.LastIdtVectoringInfo;
        g_HvHostFaultRecord.LastVmExitIntrInfo = vcpu.LastVmExitIntrInfo;
        g_HvHostFaultRecord.VmExitCount = static_cast<u64>(
            InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.VmExitCount), 0, 0));
        g_HvHostFaultRecord.LaunchStage = static_cast<u64>(
            InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.LaunchStage), 0, 0));
        g_HvHostFaultRecord.LaunchCheckStage = static_cast<u64>(
            InterlockedCompareExchange(
                const_cast<volatile LONG*>(&vcpu.LaunchCheckStage), 0, 0));
    }

    MemoryBarrier();
    constexpr ULONG_PTR kHostRootFaultMarker = 0x544F4F52ULL; // "ROOT"
    const ULONG_PTR cpuVector =
        (static_cast<ULONG_PTR>(cpu) << 32) |
        static_cast<ULONG_PTR>(g_HvHostFaultRecord.Vector);
    KeBugCheckEx(kHvFatalBugCheck,
                 kHostRootFaultMarker,
                 cpuVector,
                 static_cast<ULONG_PTR>(g_HvHostFaultRecord.ErrorCode),
                 static_cast<ULONG_PTR>(g_HvHostFaultRecord.Rip));
    __assume(0);
}

static __forceinline u32 CurrentProcessorIndex() {
    PROCESSOR_NUMBER number{};
    KeGetCurrentProcessorNumberEx(&number);
    return KeGetProcessorIndexFromNumber(&number);
}

// clear only the VMCS that this processor published after VMPTRLD. A stale or
// mismatched pointer is a hard boundary because clearing another VMCS can
// corrupt a different processor's launch state
extern "C" bool HvClearCurrentVmcsAndRecord() {
    if (!g_VcpuData) return false;
    const u32 cpu = CurrentProcessorIndex();
    if (cpu >= g_ProcessorCount) return false;

    VcpuContext* vcpu = &g_VcpuData[cpu];
    const long state = InterlockedCompareExchange(&vcpu->VmcsCurrent, 0, 0);
    if (state == VmcsCurrentStateNone) return true;
    if (state != VmcsCurrentStateActive ||
        InterlockedCompareExchange(&vcpu->VmcsCurrent,
                                    VmcsCurrentStateClearing,
                                    VmcsCurrentStateActive) !=
            VmcsCurrentStateActive) {
        vcpu->LastVmclearFlags = 1ULL;
        WriteHvTrace(vcpu, cpu, HvTraceEventContractFail,
                     vcpu->LastVmclearFlags,
                     static_cast<u64>(state));
        return false;
    }

    WriteHvTrace(vcpu, cpu, HvTraceEventPreVmclear, vcpu->VmcsPhys);
    u64 currentPhys = ~0ULL;
    const u64 ptrFlags = HvVmPtrSt(&currentPhys);
    if (!VmxOk(ptrFlags) || currentPhys == ~0ULL ||
        currentPhys != vcpu->VmcsPhys) {
        const u64 failureFlags = ptrFlags | 1ULL;
        vcpu->LastVmclearFlags = failureFlags;
        InterlockedExchange(&vcpu->VmcsCurrent,
                            VmcsCurrentStateFailed);
        WriteHvTrace(vcpu, cpu, HvTraceEventPostVmclear,
                     failureFlags, currentPhys, vcpu->VmcsPhys);
        WriteHvTrace(vcpu, cpu, HvTraceEventContractFail,
                     failureFlags, currentPhys, vcpu->VmcsPhys);
        return false;
    }

    const u64 clearFlags = HvVmClear(&currentPhys);
    vcpu->LastVmclearFlags = clearFlags;
    if (!VmxOk(clearFlags)) {
        InterlockedExchange(&vcpu->VmcsCurrent,
                            VmcsCurrentStateFailed);
        WriteHvTrace(vcpu, cpu, HvTraceEventPostVmclear,
                     clearFlags, currentPhys, vcpu->VmcsPhys);
        WriteHvTrace(vcpu, cpu, HvTraceEventContractFail,
                     clearFlags, currentPhys, vcpu->VmcsPhys);
        return false;
    }

    InterlockedExchange(&vcpu->VmcsCurrent, VmcsCurrentStateNone);
    WriteHvTrace(vcpu, cpu, HvTraceEventPostVmclear,
                 clearFlags, currentPhys, vcpu->VmcsPhys);
    return true;
}

// a VMCS clear failure leaves ownership ambiguous. Capture while VMX is still
// active, park this processor, and stop before VMXOFF or resource reclamation
extern "C" __declspec(noreturn) void HvFailVmcsClear() {
    _disable();
    HvCaptureFatalSnapshotPreVmxoff(nullptr);
    MarkCurrentVcpuParked();
    HvFatalBugCheck(nullptr);
    __assume(0);
}

static __forceinline u64 PackSegmentSelectors(u16 first, u16 second,
                                               u16 third, u16 fourth) {
    return static_cast<u64>(first) |
           (static_cast<u64>(second) << 16) |
           (static_cast<u64>(third) << 32) |
           (static_cast<u64>(fourth) << 48);
}

// VMX restores the host descriptor tables on VM-exit.  Native teardown can
// therefore use IRET only while the guest descriptor environment is unchanged.
static bool UpdateNativeTeardownContract(VcpuContext* vcpu) {
    if (!vcpu) return false;

    u64 guestCs = 0;
    u64 guestSs = 0;
    u64 guestDs = 0;
    u64 guestEs = 0;
    u64 guestFs = 0;
    u64 guestGs = 0;
    u64 guestLdtr = 0;
    u64 guestTr = 0;
    u64 guestCsLimit = 0;
    u64 guestSsLimit = 0;
    u64 guestCsAr = 0;
    u64 guestSsAr = 0;
    u64 guestGdtBase = 0;
    u64 guestGdtLimit = 0;
    u64 guestIdtBase = 0;
    u64 guestIdtLimit = 0;
    u64 guestTrBase = 0;
    u64 guestTrLimit = 0;
    u64 guestTrAr = 0;
    const bool readOk =
        VmReadChecked(GUEST_CS_SELECTOR, &guestCs) &&
        VmReadChecked(GUEST_SS_SELECTOR, &guestSs) &&
        VmReadChecked(GUEST_DS_SELECTOR, &guestDs) &&
        VmReadChecked(GUEST_ES_SELECTOR, &guestEs) &&
        VmReadChecked(GUEST_FS_SELECTOR, &guestFs) &&
        VmReadChecked(GUEST_GS_SELECTOR, &guestGs) &&
        VmReadChecked(GUEST_LDTR_SELECTOR, &guestLdtr) &&
        VmReadChecked(GUEST_TR_SELECTOR, &guestTr) &&
        VmReadChecked(GUEST_CS_LIMIT, &guestCsLimit) &&
        VmReadChecked(GUEST_SS_LIMIT, &guestSsLimit) &&
        VmReadChecked(GUEST_CS_AR_BYTES, &guestCsAr) &&
        VmReadChecked(GUEST_SS_AR_BYTES, &guestSsAr) &&
        VmReadChecked(GUEST_GDTR_BASE, &guestGdtBase) &&
        VmReadChecked(GUEST_GDTR_LIMIT, &guestGdtLimit) &&
        VmReadChecked(GUEST_IDTR_BASE, &guestIdtBase) &&
        VmReadChecked(GUEST_IDTR_LIMIT, &guestIdtLimit) &&
        VmReadChecked(GUEST_TR_BASE, &guestTrBase) &&
        VmReadChecked(GUEST_TR_LIMIT, &guestTrLimit) &&
        VmReadChecked(GUEST_TR_AR_BYTES, &guestTrAr);
    if (!readOk) {
        InterlockedExchange(&vcpu->NativeTeardownRejectMask,
                            static_cast<LONG>(HvNativeTeardownRejectVmcsRead));
        InterlockedExchange(&vcpu->NativeTeardownSafe, 0);
        return false;
    }

    const u64 guestSelectorsLow =
        PackSegmentSelectors(static_cast<u16>(guestCs), static_cast<u16>(guestSs),
                             static_cast<u16>(guestDs), static_cast<u16>(guestEs));
    const u64 guestSelectorsHigh =
        PackSegmentSelectors(static_cast<u16>(guestFs), static_cast<u16>(guestGs),
                             static_cast<u16>(guestLdtr), static_cast<u16>(guestTr));
    const bool selectorsSame =
        guestSelectorsLow == vcpu->HostSegmentSelectorsLow &&
        guestSelectorsHigh == vcpu->HostSegmentSelectorsHigh;
    const bool csSsSame =
        guestCsLimit == vcpu->HostCsLimit &&
        guestSsLimit == vcpu->HostSsLimit &&
        guestCsAr == vcpu->HostCsAr && guestSsAr == vcpu->HostSsAr;
    const bool gdtSame = guestGdtBase == vcpu->HostGdtBase &&
                         guestGdtLimit == vcpu->HostGdtLimit;
    const bool idtSame = guestIdtBase == vcpu->HostIdtBase &&
                         guestIdtLimit == vcpu->HostIdtLimit;
    const bool trSame = guestTrBase == vcpu->HostTrBase &&
                        guestTrLimit == vcpu->HostTrLimit &&
                        guestTrAr == vcpu->HostTrAr;
    const bool same = selectorsSame && csSsSame && gdtSame && idtSame && trSame;
    u32 rejectMask = HvNativeTeardownRejectNone;
    if (!selectorsSame) rejectMask |= HvNativeTeardownRejectSelector;
    if (!csSsSame) rejectMask |= HvNativeTeardownRejectCsSsLimitAr;
    if (!gdtSame) rejectMask |= HvNativeTeardownRejectGdt;
    if (!idtSame) rejectMask |= HvNativeTeardownRejectIdt;
    if (!trSame) rejectMask |= HvNativeTeardownRejectTr;
    InterlockedExchange(&vcpu->NativeTeardownRejectMask,
                        static_cast<LONG>(rejectMask));
    InterlockedExchange(&vcpu->NativeTeardownSafe, same ? 1 : 0);
    return same;
}

// called by the launch wrapper immediately before VMLAUNCH, after VMCS setup
// and the optional fault gates have succeeded. publishing this state before
// the transfer lets the restore thunk return directly to the caller without
// running compiler-generated success code in VMX non-root mode
extern "C" bool MarkCurrentVcpuLaunched() {
    if (!g_VcpuData) return false;
    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return false;
    VcpuContext* vcpu = &g_VcpuData[id];
    // Keep the numeric handoff values stable for the assembly/test contract.
    // Stage 5 is an ownership window, not proof that VMLAUNCH succeeded.
    if (InterlockedCompareExchange(&vcpu->LaunchStage, 5, 4) != 4) {
        HV_VERBOSE_PRINT("[HV] CPU %u launch marker saw unexpected stage=%ld "
                         "state=%ld; retaining VMX state\n", id,
                         InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0),
                         InterlockedCompareExchange(&vcpu->State, 0, 0));
        return false;
    }
    // StopHvCallback refuses stage 5, so this publication cannot race a
    // VMXOFF while the wrapper is transferring control to VMLAUNCH.
    const long previous = InterlockedCompareExchange(&vcpu->State,
                                                     VcpuLaunched,
                                                     VcpuVmxOn);
    if (previous != VcpuVmxOn) {
        HV_VERBOSE_PRINT("[HV] CPU %u launch marker could not publish: "
                         "state=%ld stage=%ld; retaining VMX state\n", id,
                         previous,
                         InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0));
        return false;
    }
    WriteHvTrace(vcpu, id, HvTraceEventGuestStart);
    InterlockedIncrement(&g_HvLaunchMarkedLaunched);
    return true;
}

// GuestStartThunk returns to the original DPC continuation while still in
// VMX non-root mode. Publish the active stage only from that continuation so
// a stop request can never mistake the pre-VMLAUNCH handoff for a live guest.
extern "C" void MarkCurrentVcpuRunning() {
    if (!g_VcpuData) return;
    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return;
    VcpuContext* vcpu = &g_VcpuData[id];
    if (InterlockedCompareExchange(&vcpu->State, 0, 0) != VcpuLaunched) {
        return;
    }
    const long previous = InterlockedCompareExchange(
        &vcpu->LaunchStage, LaunchStageGuestActive, LaunchStageHandoff);
    if (previous != LaunchStageHandoff && previous != LaunchStageGuestActive) {
        return;
    }
    MemoryBarrier();
    if (InterlockedCompareExchange(&vcpu->State, 0, 0) != VcpuLaunched) {
        return;
    }
    if (previous == LaunchStageHandoff) {
        WriteHvTrace(vcpu, id, HvTraceEventGuestStart);
    }
}

// Called from VMX-root fatal paths immediately before VMXOFF.  A parked CPU
// still executes the HLT loop in this image and may be interrupted by an IPI,
// so it cannot be reclaimed like a failed VMLAUNCH.
extern "C" void MarkCurrentVcpuParked() {
    if (!g_VcpuData) return;
    const u32 id = CurrentProcessorIndex();
    if (id < g_ProcessorCount) {
        VcpuContext* vcpu = &g_VcpuData[id];
        WriteHvTrace(vcpu, id, HvTraceEventPreVmxoff);
        InterlockedExchange(&vcpu->LaunchStage, LaunchStageParked);
        InterlockedExchange(&vcpu->State, VcpuParked);
    }
}

extern "C" bool MarkCurrentVcpuTearingDown() {
    if (!g_VcpuData) return false;
    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return false;
    VcpuContext* vcpu = &g_VcpuData[id];

    // StopHvCallback owns both lifecycle transitions.  This assembly marker
    // only consumes the one-shot authorization published by that callback;
    // it must never turn an unsolicited VMCALL into a native IRET path.
    if (InterlockedCompareExchange(&vcpu->TeardownRequest, 0, 0) != 1 ||
        InterlockedCompareExchange(&vcpu->State, 0, 0) !=
            VcpuTearingDown ||
        InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0) !=
            LaunchStageTeardown) {
        return false;
    }
    if (InterlockedCompareExchange(&vcpu->TeardownRequest, 0, 1) != 1) {
        return false;
    }
    MemoryBarrier();
    WriteHvTrace(vcpu, id, HvTraceEventTeardownRequest);
    return true;
}

extern "C" void MarkCurrentVcpuStopped() {
    if (!g_VcpuData) return;
    const u32 id = CurrentProcessorIndex();
    if (id < g_ProcessorCount) {
        VcpuContext* vcpu = &g_VcpuData[id];
        // the assembly marker runs before IRET while its private frame and
        // driver image are still in use; only the stop callback may publish
        // quiescence after HvCall has returned to ordinary C++ code
        if (InterlockedCompareExchange(&vcpu->TeardownQuiesced, 0, 0) == 0) {
            return;
        }
        if (InterlockedCompareExchange(&vcpu->TeardownRequest, 0, 0) != 0) {
            return;
        }
        const long state = InterlockedCompareExchange(&vcpu->State, 0, 0);
        if (state != VcpuTearingDown) return;
        if (InterlockedCompareExchange(&vcpu->State, VcpuStopped,
                                       VcpuTearingDown) != VcpuTearingDown) {
            return;
        }
        (void)InterlockedCompareExchange(&vcpu->LaunchStage,
                                          LaunchStageStopped,
                                          LaunchStageTeardown);
        WriteHvTrace(vcpu, id, HvTraceEventPostVmxoff);
    }
}
// ==============================================================================
// Helper Functions
// ==============================================================================

// ensure controls respect the msr fixed bits
u32 AdjustControls(u32 Ctl, u32 Msr) {
    ULARGE_INTEGER msrVal;
    msrVal.QuadPart = __readmsr(Msr);
    Ctl &= msrVal.HighPart; // clear bits that must be 0
    Ctl |= msrVal.LowPart;  // set bits that must be 1
    return Ctl;
}

// ensure cr0/cr4 respect vmx fixed bits
u64 AdjustCr0(u64 Cr0) {
    const u64 fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    const u64 fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    return (Cr0 & fixed1) | fixed0;
}

u64 AdjustCr4(u64 Cr4) {
    const u64 fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    const u64 fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    return (Cr4 & fixed1) | fixed0;
}

// passive level memory allocator
// replaced ExAllocatePool2 with ExAllocatePoolWithTag for broader compatibility
void* AllocContiguous(SIZE_T Size, u64* Phys) {
    PHYSICAL_ADDRESS low = {};
    PHYSICAL_ADDRESS high = {};
    high.QuadPart = g_VmxRequires32BitPhysicalAddress ? 0xFFFFFFFFLL : -1LL;
    PHYSICAL_ADDRESS boundary = {};
    void* virt = MmAllocateContiguousMemorySpecifyCache(
        Size, low, high, boundary, MmCached);
    if (virt) {
        RtlZeroMemory(virt, Size);
        *Phys = MmGetPhysicalAddress(virt).QuadPart;
        if ((*Phys & (PAGE_SIZE - 1)) != 0 ||
            (g_VmxRequires32BitPhysicalAddress && *Phys > 0xFFFFFFFFULL)) {
            MmFreeContiguousMemory(virt);
            *Phys = 0;
            return nullptr;
        }
    }
    return virt;
}

// ==============================================================================
// VM-Exit Handling
// ==============================================================================

static void InjectGuestException(GuestContext* c, u8 vector, bool hasErrorCode,
                                 u32 errorCode = 0) {
    if (!c) return;
    const u32 id = CurrentProcessorIndex();
    VcpuContext* vcpu =
        g_VcpuData && id < g_ProcessorCount ? &g_VcpuData[id] : nullptr;
    // VmExitHandler captured these one-shot fields before clearing them. A
    // fresh VMREAD here would observe a different VMCS transaction after a
    // handler write and could silently merge two events into a double fault.
    const bool eventStateKnown =
        vcpu && InterlockedCompareExchange(&vcpu->LastEventSnapshotValid,
                                           0, 0) != 0;
    const u64 entryIntrInfo = vcpu ? vcpu->LastVmEntryIntrInfo : 0;
    const u64 exitIntrInfo = vcpu ? vcpu->LastVmExitIntrInfo : 0;
    const u64 idtVectoringInfo = vcpu ? vcpu->LastIdtVectoringInfo : 0;
    const u64 pendingDebug = vcpu ? vcpu->LastGuestPendingDbgExceptions : 0;
    if (!vcpu || !eventStateKnown || vector > 31U ||
        (entryIntrInfo & VM_ENTRY_INTR_INFO_VALID) != 0 ||
        (exitIntrInfo & VM_ENTRY_INTR_INFO_VALID) != 0 ||
        (idtVectoringInfo & VM_ENTRY_INTR_INFO_VALID) != 0 ||
        pendingDebug != 0) {
        // Combining an injected exception with an in-flight event requires
        // Intel's exception-pair state machine. Until that is implemented,
        // preserve the first event and stop instead of risking #DF/#TF.
        c->AbortVm = 0;
        c->HaltVm = 1;
        return;
    }
    u32 info = VM_ENTRY_INTR_INFO_VALID | VM_ENTRY_INTR_TYPE_HARDWARE_EXCEPTION |
               static_cast<u32>(vector);
    if (hasErrorCode) info |= VM_ENTRY_INTR_INFO_DELIVER_ERROR_CODE;
    if (!VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, info) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE,
                        hasErrorCode ? errorCode : 0) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, 0)) {
        c->HaltVm = 1;
    }
}

// handle hypervisor unload requests
bool HandleVmCall(GuestContext* Ctx) {
    if (!Ctx) return false;
    // calling convention: rcx = magic, rdx = command
    if ((Ctx->GuestCs & 3U) == 0 &&
        Ctx->Rcx == HYPERVISOR_MAGIC && Ctx->Rdx == VMCALL_UNLOAD) {
        // VmExitHandler advances GUEST_RIP exactly once after this routine.
        // The assembly epilogue then VMXOFFs and returns through a real IRET
        // frame, allowing StopHvCallback's normal C++ epilogue to run.
        RequestAuthenticatedUnload(Ctx, VM_EXIT_REASON_VMCALL);
        return Ctx->AbortVm != 0;
    }
    // The unload token is a ring-0 service call.  A guest CPL3 attempt must
    // not be allowed to select the native teardown path.
    InjectGuestException(Ctx, 13, true, 0);
    return false;
}

bool HandleMsrRead(GuestContext* Ctx) {
    if (!Ctx) return false;
    if ((Ctx->GuestCs & 3U) != 0) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }
    // RDMSR: reads the MSR specified by ECX into EDX:EAX
    u32 msrIndex = static_cast<u32>(Ctx->Rcx);

    // VMX entry/exit state owns these MSRs.  Read the guest copy rather than
    // exposing the host copy while executing in VMX root mode.
    if (msrIndex == MSR_FS_BASE) {
        const u64 value = Ctx->GuestFsBase;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_GS_BASE) {
        const u64 value = Ctx->GuestGsBase;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_KERNEL_GS_BASE) {
        const u64 value = Ctx->GuestKernelGsBase;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_EFER) {
        const u64 value = Ctx->GuestEfer;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_PAT) {
        const u64 value = Ctx->GuestPat;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_DEBUGCTL) {
        const u64 value = Ctx->GuestDebugctl;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_CS) {
        const u64 value = Ctx->GuestSysenterCs;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_ESP) {
        const u64 value = Ctx->GuestSysenterEsp;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_EIP) {
        const u64 value = Ctx->GuestSysenterEip;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }

    if (msrIndex == MSR_IA32_XSS) {
        if (!g_XsavesEnabled) {
            // IA32_XSS is not part of the legacy FXSAVE/ordinary XSAVE
            // contract. Keep the virtual selector at its architectural reset
            // value instead of exposing a root-mode MSR or rejecting a
            // harmless zero probe on processors without XSAVES.
            Ctx->Rax = 0;
            Ctx->Rdx = 0;
            return true;
        }
        const u64 value = Ctx->GuestXss;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_U_CET || msrIndex == MSR_IA32_PL3_SSP) {
        // This exit is configured only when CET_U cannot be preserved. Keep
        // the hidden guest contract deterministic instead of exposing root
        // state through the VM-exit handler.
        Ctx->Rax = 0;
        Ctx->Rdx = 0;
        return true;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_S_CET) {
        const u64 value = Ctx->GuestSCet;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_INTERRUPT_SSP_TABLE) {
        const u64 value = Ctx->GuestInterruptSspTable;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_PL0_SSP) {
        const u64 value = Ctx->GuestSsp;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (g_CetVmcsEnabled &&
        (msrIndex == MSR_IA32_PL1_SSP || msrIndex == MSR_IA32_PL2_SSP)) {
        Ctx->Rax = 0;
        Ctx->Rdx = 0;
        return true;
    }

    if (IsIntelPtMsr(msrIndex) || IsCetStateMsr(msrIndex)) {
        // PT and unsupported CET are hidden from the guest.  Reject the
        // access architecturally instead of entering the machine-wide fatal
        // path; a guest #GP keeps the original RIP available to KD.
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }
    if (msrIndex == MSR_IA32_XFD || msrIndex == MSR_IA32_XFD_ERR) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }

    InjectGuestException(Ctx, 13, true, 0);
    return false;
}

bool HandleMsrWrite(GuestContext* Ctx) {
    if (!Ctx) return false;
    if ((Ctx->GuestCs & 3U) != 0) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }
    // WRMSR: writes the value in EDX:EAX to the MSR specified by ECX
    u32 msrIndex = static_cast<u32>(Ctx->Rcx);
    ULARGE_INTEGER value;
    value.LowPart  = static_cast<u32>(Ctx->Rax);
    value.HighPart = static_cast<u32>(Ctx->Rdx);

    if (msrIndex == MSR_FS_BASE) {
        if (!IsCanonical(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_FS_BASE, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestFsBase = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_GS_BASE) {
        if (!IsCanonical(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_GS_BASE, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestGsBase = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_KERNEL_GS_BASE) {
        if (!IsCanonical(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        Ctx->GuestKernelGsBase = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_EFER) {
        const u64 oldValue = Ctx->GuestEfer;
        // This late-launch monitor cannot virtualize the long-mode transition
        // bits. Preserve every non-writable bit exactly and inject #GP instead
        // of silently rewriting an illegal architectural request.
        constexpr u64 kWritableEferBits = EFER_SCE | EFER_NXE;
        if ((value.QuadPart ^ oldValue) & ~kWritableEferBits) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        int regs[4] = {};
        __cpuidex(regs, 0x80000000, 0);
        if (static_cast<u32>(regs[0]) < 0x80000001U) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        __cpuidex(regs, 0x80000001, 0);
        if ((value.QuadPart & EFER_NXE) != 0 && (regs[3] & (1 << 20)) == 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        const u64 newValue = value.QuadPart;
        if (!VmWriteChecked(GUEST_EFER, newValue)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestEfer = newValue;
        return true;
    }
    if (msrIndex == MSR_IA32_PAT) {
        if (!IsValidPatValue(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_PAT, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestPat = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_DEBUGCTL) {
        if (!IsValidDebugctl(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_DEBUGCTL, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestDebugctl = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_CS) {
        // IA32_SYSENTER_CS is a 32-bit selector MSR.  Reserved upper bits
        // must be zero; reject malformed writes with the architectural #GP
        // instead of allowing a VM-entry consistency failure later.
        if ((value.QuadPart & ~0xFFFFULL) != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_SYSENTER_CS, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestSysenterCs = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_ESP) {
        if (!IsCanonical(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_SYSENTER_ESP, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestSysenterEsp = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_EIP) {
        if (!IsCanonical(value.QuadPart)) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_SYSENTER_EIP, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestSysenterEip = value.QuadPart;
        return true;
    }

    if (msrIndex == MSR_IA32_XSS) {
        const u32 id = CurrentProcessorIndex();
        VcpuContext* vcpu =
            g_VcpuData && id < g_ProcessorCount ? &g_VcpuData[id] : nullptr;
        if (vcpu) {
            InterlockedIncrement(&vcpu->XssWriteExitCount);
            vcpu->LastXssWritePrevious = Ctx->GuestXss;
            vcpu->LastXssWriteRequested = value.QuadPart;
            WriteHvTrace(vcpu, id, HvTraceEventXssWrite, Ctx->GuestXss,
                         value.QuadPart, g_XsavesMask, g_EnumeratedXssMask);
        }

        if (!g_XsavesEnabled) {
            if (value.QuadPart != 0) {
                if (vcpu) {
                    InterlockedIncrement(&vcpu->XssWriteRejectCount);
                    Ctx->AbortVm = 0;
                    Ctx->HaltVm = 1;
                } else {
                    InjectGuestException(Ctx, 13, true, 0);
                }
                return false;
            }
            Ctx->GuestXss = 0;
            if (vcpu) vcpu->GuestXss = 0;
            return true;
        }

        // The fixed XSAVES frame can virtualize selector changes only inside
        // its immutable mask. Catch a later LBR/HWP/etc. selection at WRMSR
        // instead of discovering a different compacted layout on another exit.
        if ((value.QuadPart & ~g_GuestXssWriteMask) != 0 ||
            (value.QuadPart & ~g_XsavesMask) != 0 ||
            (value.QuadPart & ~g_EnumeratedXssMask) != 0) {
            if (vcpu) {
                InterlockedIncrement(&vcpu->XssWriteRejectCount);
                Ctx->AbortVm = 0;
                Ctx->HaltVm = 1;
            } else {
                InjectGuestException(Ctx, 13, true, 0);
            }
            return false;
        }
        Ctx->GuestXss = value.QuadPart;
        if (vcpu) vcpu->GuestXss = value.QuadPart;
        return true;
    }
    if (msrIndex == MSR_IA32_U_CET || msrIndex == MSR_IA32_PL3_SSP) {
        // This branch is reachable only when CET_U is enumerated but is not
        // owned by the fixed XSAVES frame. Match the hidden guest contract
        // with an architectural fault rather than changing root-mode state.
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_S_CET) {
        // a non-zero supervisor CET request needs native shadow-stack handling
        if (value.QuadPart != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_S_CET, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestSCet = value.QuadPart;
        return true;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_INTERRUPT_SSP_TABLE) {
        if (value.QuadPart != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_INTR_SSP_TABLE, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestInterruptSspTable = value.QuadPart;
        return true;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_PL0_SSP) {
        if (value.QuadPart != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        if (!VmWriteChecked(GUEST_SSP, value.QuadPart)) {
            Ctx->HaltVm = 1;
            return false;
        }
        Ctx->GuestSsp = value.QuadPart;
        return true;
    }
    if (g_CetVmcsEnabled &&
        (msrIndex == MSR_IA32_PL1_SSP || msrIndex == MSR_IA32_PL2_SSP)) {
        // PL1 and PL2 have no VMCS fields in this fixed contract
        if (value.QuadPart != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        return true;
    }

    if (IsIntelPtMsr(msrIndex) || IsCetStateMsr(msrIndex)) {
        // Hidden PT/CET state is a guest-visible unsupported MSR, not a
        // reason to bugcheck the whole host.  Inject #GP and leave RIP
        // unchanged so the guest exception machinery can handle it.
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }
    if (msrIndex == MSR_IA32_XFD || msrIndex == MSR_IA32_XFD_ERR) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }

    InjectGuestException(Ctx, 13, true, 0);
    return false;
}

static bool SetMsrBitmapIntercept(void* bitmap, u32 msr,
                                  bool interceptRead, bool interceptWrite) {
    if (!bitmap) return false;
    auto bytes = static_cast<u8*>(bitmap);
    u32 bitIndex = 0;
    SIZE_T readBase = 0;
    SIZE_T writeBase = 0;
    if (msr <= 0x1FFFU) {
        bitIndex = msr;
        readBase = 0;
        writeBase = 0x800;
    } else if (msr >= 0xC0000000U && msr <= 0xC0001FFFU) {
        bitIndex = msr - 0xC0000000U;
        readBase = 0x400;
        writeBase = 0xC00;
    } else {
        return false;
    }
    const SIZE_T byteIndex = static_cast<SIZE_T>(bitIndex >> 3);
    const u8 bit = static_cast<u8>(1U << (bitIndex & 7U));
    if (interceptRead) bytes[readBase + byteIndex] |= bit;
    if (interceptWrite) bytes[writeBase + byteIndex] |= bit;
    return true;
}

static bool ConfigureMsrBitmap(VcpuContext* vcpu) {
    if (!vcpu || !vcpu->MsrBitmapVirt) return false;

    // Keep ordinary MSRs native. IA32_XSS is the one guarded selector because
    // the VM-exit XSAVES frame has an immutable supervisor-component mask.
    RtlZeroMemory(vcpu->MsrBitmapVirt, PAGE_SIZE);
    return SetMsrBitmapIntercept(vcpu->MsrBitmapVirt, MSR_IA32_XSS, true, true);
}

static __forceinline u32 ControlMsr(u64 vmxBasic, u32 legacyMsr, u32 trueMsr) {
    return (vmxBasic & VMX_BASIC_TRUE_CONTROLS) ? trueMsr : legacyMsr;
}

static __forceinline u32 ControlMandatoryOn(u32 msr) {
    return static_cast<u32>(__readmsr(msr));
}

static __forceinline u64 GetGpr(const GuestContext* c, u8 reg) {
    switch (reg) {
        case 0: return c->Rax; case 1: return c->Rcx; case 2: return c->Rdx; case 3: return c->Rbx;
        case 4: return c->GuestRsp; case 5: return c->Rbp; case 6: return c->Rsi; case 7: return c->Rdi;
        case 8: return c->R8;  case 9: return c->R9;  case 10: return c->R10; case 11: return c->R11;
        case 12: return c->R12; case 13: return c->R13; case 14: return c->R14; case 15: return c->R15;
        default: return 0;
    }
}

static __forceinline bool SetGpr(GuestContext* c, u8 reg, u64 v) {
    switch (reg) {
        case 0:
            c->Rax = v;
            return true;
        case 1:
            c->Rcx = v;
            return true;
        case 2:
            c->Rdx = v;
            return true;
        case 3:
            c->Rbx = v;
            return true;
        case 4:
            c->GuestRsp = v;
            return VmWriteChecked(GUEST_RSP, v);
        case 5:
            c->Rbp = v;
            return true;
        case 6: c->Rsi = v;
            return true;
        case 7:
            c->Rdi = v;
            return true;
        case 8:
            c->R8 = v;
            return true;
        case 9:
            c->R9 = v;
            return true;
        case 10:
            c->R10 = v;
            return true;
        case 11:
            c->R11 = v;
            return true;
        case 12:
            c->R12 = v;
            return true;
        case 13:
            c->R13 = v;
            return true;
        case 14: c->R14 = v;
            return true;
        case 15:
            c->R15 = v;
            return true;
        default:
            return false;
    }
}

static bool HandleCrAccess(GuestContext* c) {
    if (!c) return false;
    if ((c->GuestCs & 3U) != 0) {
        InjectGuestException(c, 13, true, 0);
        return false;
    }
    u64 qual = 0;
    if (!VmReadChecked(EXIT_QUALIFICATION, &qual)) {
        c->HaltVm = 1;
        return false;
    }
    const u8 crNum = static_cast<u8>(qual & 0xF);
    const u8 accessType = static_cast<u8>((qual >> 4) & 0x3);
    const u8 gpr = static_cast<u8>((qual >> 8) & 0xF);

    if (accessType == 0) {
        const u64 value = GetGpr(c, gpr);
        if (crNum == 0) {
            constexpr u64 kRequiredCr0Bits = (1ULL << 0) | (1ULL << 31);
            if (!IsFixedCrValueValid(value, MSR_IA32_VMX_CR0_FIXED0,
                                     MSR_IA32_VMX_CR0_FIXED1) ||
                (value & kRequiredCr0Bits) != kRequiredCr0Bits ||
                (c->GuestCr4 & (1ULL << 5)) == 0 ||
                ((c->GuestCr4 & CR4_PCIDE) != 0 &&
                 (value & (1ULL << 31)) == 0)) {
                InjectGuestException(c, 13, true, 0);
                return false;
            }
            const u64 newCr0 = value;
            if (!VmWriteChecked(GUEST_CR0, newCr0) ||
                !VmWriteChecked(CONTROL_CR0_READ_SHADOW, newCr0)) {
                c->HaltVm = 1;
                return 0;
            }
            c->GuestCr0 = newCr0;
            return true;
        }
        if (crNum == 4) {
            constexpr u64 kRequiredCr4Bits = 1ULL << 5;
            const bool requiredOsxsave = g_XstateMode != XstateSaveFxsave;
            if (((value & CR4_OSXSAVE) != 0) != requiredOsxsave) {
                InjectGuestException(c, 13, true, 0);
                return 0;
            }
            if ((value & CR4_FRED) != 0) {
                InjectGuestException(c, 13, true, 0);
                return 0;
            }
            if ((value & CR4_CET) != 0 && !g_CetVmcsEnabled) {
                InjectGuestException(c, 13, true, 0);
                return 0;
            }
            const u32 cpuId = CurrentProcessorIndex();
            const VcpuContext* currentVcpu =
                g_VcpuData && cpuId < g_ProcessorCount
                    ? &g_VcpuData[cpuId]
                    : nullptr;
            if ((value & CR4_PKE) != 0 &&
                (!currentVcpu || (currentVcpu->HostXcr0 & XCR0_PKRU) == 0)) {
                InjectGuestException(c, 13, true, 0);
                return 0;
            }
            const u64 requestedCr4 = value | CR4_VMXE;
            if (!IsFixedCrValueValid(requestedCr4, MSR_IA32_VMX_CR4_FIXED0,
                                     MSR_IA32_VMX_CR4_FIXED1) ||
                (value & kRequiredCr4Bits) == 0 ||
                (c->GuestCr0 & (1ULL << 31)) == 0) {
                InjectGuestException(c, 13, true, 0);
                return false;
            }
            u64 currentCr3 = 0;
            if (!VmReadChecked(GUEST_CR3, &currentCr3)) {
                c->HaltVm = 1;
                return false;
            }
            if (!IsValidArchitecturalCr3(currentCr3, requestedCr4)) {
                InjectGuestException(c, 13, true, 0);
                return false;
            }
            const u64 actualCr4 = requestedCr4;
            const u64 cr4GuestHostMask = GetCr4GuestHostMask();
            if (!VmWriteChecked(GUEST_CR4, actualCr4) ||
                !VmWriteChecked(CONTROL_CR4_READ_SHADOW,
                                value & cr4GuestHostMask)) {
                c->HaltVm = 1;
                return false;
            }
            c->GuestCr4 = actualCr4;
            return true;
        }
        if (crNum == 3) {
            u64 guestCr4 = 0;
            if (!VmReadChecked(GUEST_CR4, &guestCr4)) {
                c->HaltVm = 1;
                return false;
            }
            if (!IsValidCr3(value, guestCr4)) {
                InjectGuestException(c, 13, true, 0);
                return false;
            }
            const u64 normalizedCr3 = NormalizeCr3(value, guestCr4);
            if (!VmWriteChecked(GUEST_CR3, normalizedCr3)) {
                c->HaltVm = 1;
                return false;
            }
            c->GuestCr3 = normalizedCr3;
            return true;
        }
        InjectGuestException(c, 6, false);
        return false;
    }
    if (accessType == 1) {
        if (crNum == 0) {
            u64 value = 0;
            if (!VmReadChecked(GUEST_CR0, &value) || !SetGpr(c, gpr, value)) {
                c->HaltVm = 1;
            }
            return c->HaltVm == 0;
        }
        if (crNum == 4) {
            u64 guestCr4 = 0;
            u64 cr4GuestHostMask = 0;
            u64 cr4ReadShadow = 0;
            if (!VmReadChecked(GUEST_CR4, &guestCr4) ||
                !VmReadChecked(CONTROL_CR4_GUEST_HOST_MASK,
                               &cr4GuestHostMask) ||
                !VmReadChecked(CONTROL_CR4_READ_SHADOW, &cr4ReadShadow)) {
                c->HaltVm = 1;
                return false;
            }
            const u64 value = (guestCr4 & ~cr4GuestHostMask) |
                              (cr4ReadShadow & cr4GuestHostMask);
            if (!SetGpr(c, gpr, value)) c->HaltVm = 1;
            return c->HaltVm == 0;
        }
        if (crNum == 3) {
            u64 value = 0;
            if (!VmReadChecked(GUEST_CR3, &value) ||
                !SetGpr(c, gpr, value)) {
                c->HaltVm = 1;
            }
            return c->HaltVm == 0;
        }
        InjectGuestException(c, 6, false);
        return false;
    }

    // CLTS/LMSW (access types 2/3) are uncommon on modern Windows.  They are
    // not emulated here; inject #UD instead of silently advancing RIP.
    InjectGuestException(c, 6, false);
    return false;
}

// XCR0 is a per-logical-processor register and is not part of the VMCS
// guest/host state. The VM-exit assembly captures the guest mask, switches to
// the host mask for C++, and restores the guest mask before VMRESUME. Accept
// only architectural XCR0 subsets that fit the immutable frame budget.
static bool HandleXsetbv(GuestContext* c, VcpuContext* vcpu) {
    if (!c || !vcpu) return false;
    if ((c->GuestCs & 3U) != 0) {
        InjectGuestException(c, 13, true, 0);
        return false;
    }
    if (g_XstateMode == XstateSaveFxsave) {
        InjectGuestException(c, 6, false);
        return false;
    }

    // If the live mask has already diverged, the assembly prologue could not
    // have been given a host-compatible XSAVE layout. Do not attempt another
    // VMRESUME; park through the existing fail-closed path.
    u64 liveXcr0 = 0;
    __try {
        liveXcr0 = _xgetbv(0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        c->HaltVm = 1;
        return false;
    }
    if (liveXcr0 != vcpu->HostXcr0) {
        c->HaltVm = 1;
        return false;
    }

    const u32 xcrIndex = static_cast<u32>(c->Rcx);
    const u64 requested = (static_cast<u64>(static_cast<u32>(c->Rdx)) << 32) |
                          static_cast<u32>(c->Rax);
    InterlockedIncrement(&vcpu->XsetbvExitCount);
    vcpu->LastXsetbvPrevious = c->GuestXcr0;
    vcpu->LastXsetbvRequested = requested;
    WriteHvTrace(vcpu, CurrentProcessorIndex(), HvTraceEventXsetbv,
                 c->GuestXcr0, requested, vcpu->HostXcr0, c->GuestCr4);
    if (xcrIndex != 0 || (requested & 0x3ULL) != 0x3ULL ||
        (requested & ~vcpu->HostXcr0) != 0) {
        // #GP is an error-code exception; XSETBV reports #GP(0). Mark the
        // VM-entry injection accordingly so the guest exception frame has the
        // architectural fifth word and does not corrupt the guest stack.
        InjectGuestException(c, 13, true, 0);
        return false;
    }

    // Reject bits the processor does not enumerate in CPUID.(EAX=0Dh,ECX=0).
    // Validate the architectural request first. This diagnostic build still uses
    // one immutable XCR0 layout and will fail-stop below if Windows requests
    // a different otherwise-valid selector.
    int regs[4] = {};
    __cpuidex(regs, 0xD, 0);
    const u64 supported = static_cast<u32>(regs[0]) |
                          (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    const u64 requestedMpx = requested & XCR0_MPX;
    const u64 requestedAvx512 = requested & XCR0_AVX512;
    const u64 requestedAmx = requested & XCR0_AMX;
    if ((requested & ~supported) != 0 ||
        (requestedMpx != 0 && requestedMpx != XCR0_MPX) ||
        (requestedAvx512 != 0 &&
         (requestedAvx512 != XCR0_AVX512 ||
          (requested & XCR0_AVX) == 0)) ||
        (requestedAmx != 0 && requestedAmx != XCR0_AMX) ||
        ((requested & XCR0_PKRU) != 0 &&
         (c->GuestCr4 & CR4_PKE) == 0) ||
        ((requested & XCR0_PKRU) == 0 &&
         (c->GuestCr4 & CR4_PKE) != 0)) {
        InjectGuestException(c, 13, true, 0);
        return false;
    }

    u32 areaSize = 0;
    if (g_XsavesEnabled) {
        u64 xssCapabilities = 0;
        if (!ComputeXsaveAreaSize(requested, g_XsavesMask,
                                  &xssCapabilities, &areaSize)) {
            InjectGuestException(c, 13, true, 0);
            return false;
        }
    } else if (!ComputeStandardXsaveAreaSize(requested, &areaSize)) {
        InjectGuestException(c, 13, true, 0);
        return false;
    }
    if (areaSize > VMEXIT_XSAVE_MAX) {
        InjectGuestException(c, 13, true, 0);
        return false;
    }

    // A dynamic XCR0 change would alter the guest state contract. Record the
    // request but do not silently widen the fixed VM-exit preservation image.
    // A future version can virtualize a second per-vCPU image; this diagnostic
    // build fails closed before resuming with an ambiguous layout.
    if (requested != vcpu->HostXcr0) {
        WriteHvTrace(vcpu, CurrentProcessorIndex(), HvTraceEventXsetbv,
                     c->GuestXcr0, requested, vcpu->HostXcr0, 1);
        c->AbortVm = 0;
        c->HaltVm = 1;
        return false;
    }
    c->GuestXcr0 = requested;
    vcpu->GuestXcr0 = requested;
    return true;
}

extern "C" void VmExitHandler(GuestContext* Ctx) {
    if (!Ctx) return;
    const u32 cpuId = CurrentProcessorIndex();
    if (!g_VcpuData || cpuId >= g_ProcessorCount) {
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        return;
    }
    VcpuContext* vcpu = &g_VcpuData[cpuId];

    // CR2 is not part of the VMCS. capture it before the root handler performs
    // any operation that could itself fault so a guest #PF -> #DF chain still
    // leaves the original linear address in the per-CPU record.
    vcpu->LastGuestCr2 = __readcr2();

    *reinterpret_cast<u64*>(reinterpret_cast<u8*>(Ctx) +
                           VMEXIT_NATIVE_IDT_BASE_OFFSET) = vcpu->HostIdtBase;
    *reinterpret_cast<u64*>(reinterpret_cast<u8*>(Ctx) +
                           VMEXIT_NATIVE_IDT_LIMIT_OFFSET) = vcpu->HostIdtLimit;
    if (AcquireFatalSnapshotCommitState(vcpu) != HvFatalSnapshotEmpty) {
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        return;
    }
    u64 rawReasonValue = 0;
    u64 exitLen = 0;
    if (!VmReadChecked(VM_EXIT_REASON, &rawReasonValue)) {
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        return;
    }
    const u32 rawExitReason = static_cast<u32>(rawReasonValue);
    const u32 basicExitReason = rawExitReason & 0xFFFFU;
    const bool entryFailure = (rawExitReason & 0x80000000U) != 0;
    // Intel leaves VM_EXIT_INSTRUCTION_LEN unmodified for VM-entry failure;
    // only read it for a normal guest exit where this field is defined
    if (!entryFailure && !VmReadChecked(VM_EXIT_INSTRUCTION_LEN, &exitLen)) {
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        return;
    }
    const u32 exitMsrIndex =
        (basicExitReason == VM_EXIT_REASON_RDMSR ||
         basicExitReason == VM_EXIT_REASON_WRMSR)
            ? static_cast<u32>(Ctx->Rcx)
            : 0U;
    const u64 exitMsrValue =
        (basicExitReason == VM_EXIT_REASON_RDMSR ||
         basicExitReason == VM_EXIT_REASON_WRMSR)
            ? static_cast<u64>(static_cast<u32>(Ctx->Rax)) |
                  (static_cast<u64>(static_cast<u32>(Ctx->Rdx)) << 32)
            : 0ULL;
    const u64 ExitReason = basicExitReason;
    const u64 ExitLen = exitLen;

    // Start a new diagnostic transaction. The immediate VMfailValid error is
    // captured by AbortHvLaunch or HandleVmResumeFailure and is not part of a
    // later VM-exit snapshot.
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(
                              &vcpu->VmcsDiagnosticValidity),
                          static_cast<LONG64>(HvVmcsValidityNone));
    vcpu->LastVmInstructionError = 0;
    vcpu->LastExitReason = static_cast<long>(basicExitReason);
    vcpu->LastExitReasonRaw = rawExitReason;
    vcpu->LastExitReasonBasic = basicExitReason;
    vcpu->LastExitEntryFailure = entryFailure ? 1U : 0U;
    vcpu->LastExitMsrIndex = exitMsrIndex;
    vcpu->LastExitMsrReserved = 0;
    vcpu->LastExitMsrValue = exitMsrValue;
    vcpu->LastExitInstructionLength = entryFailure ? 0 : exitLen;
    SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityExitReason);
    if (!entryFailure) {
        SetVmcsDiagnosticValidity(vcpu,
                                  HvVmcsValidityExitInstructionLength);
        // Record the boundary before optional event-state reads. If one of
        // those reads fails, the trace still proves that hardware reached the
        // VM-exit handler and preserves the raw reason for postmortem work.
        WriteHvTrace(vcpu, cpuId, HvTraceEventVmexitEntry, rawExitReason,
                     static_cast<u64>(entryFailure), exitMsrIndex,
                     exitMsrValue);
    }

    if (entryFailure) {
        // A VM-entry failure is not a running guest exit. Intel specifies that
        // the guest-state and most event fields remain unmodified. Keep only
        // the reason and its qualification, and never treat
        // VM_INSTRUCTION_ERROR as a current VM-exit value.
        InterlockedExchange(&vcpu->LastEventSnapshotValid, 0);
        u64 entryFailureQualification = 0;
        if (IsVmEntryFailureQualificationDefined(rawExitReason) &&
            VmReadChecked(EXIT_QUALIFICATION, &entryFailureQualification)) {
            vcpu->LastExitQualification = entryFailureQualification;
            SetVmcsDiagnosticValidity(vcpu,
                                      HvVmcsValidityExitQualification);
        } else {
            // Intel leaves this field unmodified for entry-failure reason 41
            // and for reserved reasons. Keep the old value only as storage.
            ClearVmcsDiagnosticValidity(vcpu,
                                        HvVmcsValidityExitQualification);
        }
        WriteHvTrace(vcpu, cpuId, HvTraceEventVmEntryFailure,
                     rawExitReason, basicExitReason);
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        return;
    }

    // Snapshot every event-delivery field while the VMCS still describes this
    // exit. Do this before any VMCS write or guest RIP read: a failed write
    // must never destroy the evidence needed to distinguish VM-entry failure,
    // IDT vectoring, and an injected exception.
    InterlockedExchange(&vcpu->LastEventSnapshotValid, 0);
    MemoryBarrier();
    u64 entryIntrInfo = 0;
    u64 entryIntrError = 0;
    u64 entryInstructionLength = 0;
    u64 exitIntrInfo = 0;
    u64 exitIntrError = 0;
    u64 idtVectoringInfo = 0;
    u64 idtVectoringError = 0;
    u64 guestInterruptibility = 0;
    u64 guestActivity = 0;
    u64 pendingDebug = 0;
    bool eventStateValid = true;
    eventStateValid &=
        VmReadChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, &entryIntrInfo);
    eventStateValid &= VmReadChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE,
                                     &entryIntrError);
    eventStateValid &= VmReadChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH,
                                     &entryInstructionLength);
    eventStateValid &= VmReadChecked(VM_EXIT_INTR_INFO, &exitIntrInfo);
    eventStateValid &= VmReadChecked(VM_EXIT_INTR_ERROR_CODE, &exitIntrError);
    eventStateValid &=
        VmReadChecked(VM_EXIT_IDT_VECTORING_INFO, &idtVectoringInfo);
    eventStateValid &= VmReadChecked(VM_EXIT_IDT_VECTORING_ERROR_CODE,
                                     &idtVectoringError);
    eventStateValid &= VmReadChecked(GUEST_INTERRUPTIBILITY_INFO,
                                     &guestInterruptibility);
    eventStateValid &= VmReadChecked(GUEST_ACTIVITY_STATE, &guestActivity);
    eventStateValid &=
        VmReadChecked(GUEST_PENDING_DBG_EXCEPTIONS, &pendingDebug);
    if (!eventStateValid) {
        // Event metadata is part of the continuation contract. Without it,
        // neither reinjection nor native teardown can be proven safe.
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }
    // Publish the complete event image only after every VMREAD succeeded.
    // Readers therefore see either the previous complete image or this one,
    // never a mixture created by a partial VMCS transaction.
    vcpu->LastVmEntryIntrInfo = static_cast<u32>(entryIntrInfo);
    vcpu->LastVmEntryIntrError = static_cast<u32>(entryIntrError);
    vcpu->LastVmEntryInstructionLength =
        static_cast<u32>(entryInstructionLength);
    vcpu->LastVmExitIntrInfo = static_cast<u32>(exitIntrInfo);
    vcpu->LastVmExitIntrError = static_cast<u32>(exitIntrError);
    vcpu->LastIdtVectoringInfo = static_cast<u32>(idtVectoringInfo);
    vcpu->LastIdtVectoringError = static_cast<u32>(idtVectoringError);
    vcpu->LastGuestInterruptibility =
        static_cast<u32>(guestInterruptibility);
    vcpu->LastGuestActivity = static_cast<u32>(guestActivity);
    vcpu->LastGuestPendingDbgExceptions = static_cast<u32>(pendingDebug);
    MemoryBarrier();
    InterlockedExchange(&vcpu->LastEventSnapshotValid, 1);
    SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityEventState);
    const long exitCount = InterlockedIncrement(&vcpu->VmExitCount);
    if (exitCount == 1) {
        // The first non-entry exit is the first proof that GuestStartThunk
        // returned into the guest and later reached a VM-exit boundary.  It
        // is deliberately recorded here instead of adding code to the pure
        // restore thunk.
        InterlockedIncrement(&g_HvLaunchGuestStarted);
        InterlockedIncrement(&g_HvLaunchFirstVmExitEntered);
    }
    // This monitor has no pending-event queue or interrupt-window state
    // machine. Never clear an in-flight IDT delivery and resume as if it had
    // completed, because that can turn one lost exception into a fault chain.
    // Keep the published snapshot intact so the fatal path and KD can inspect
    // the exact vectoring fields that stopped this vCPU.
    if ((idtVectoringInfo & VM_ENTRY_INTR_INFO_VALID) != 0) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventFatalVmexit,
                     rawExitReason, idtVectoringInfo, idtVectoringError,
                     exitIntrInfo);
        RequestFatalStop(Ctx);
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }
    // A VM-entry interruption field is consumed only once by hardware. Clear
    // it only after the complete event snapshot has been published so a
    // previous injected #GP/#UD cannot be delivered again after resume.
    if (!VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, 0)) {
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }

    // synchronize context
    if (!VmReadChecked(GUEST_RIP, &Ctx->GuestRip) ||
        !VmReadChecked(GUEST_RSP, &Ctx->GuestRsp) ||
        !VmReadChecked(GUEST_RFLAGS, &Ctx->Rflags) ||
        !VmReadChecked(GUEST_CS_SELECTOR, &Ctx->GuestCs) ||
        !VmReadChecked(GUEST_SS_SELECTOR, &Ctx->GuestSs) ||
        !VmReadChecked(GUEST_CR3, &Ctx->GuestCr3) ||
        !VmReadChecked(GUEST_CR4, &Ctx->GuestCr4) ||
        !VmReadChecked(GUEST_CR0, &Ctx->GuestCr0) ||
        !VmReadChecked(GUEST_FS_BASE, &Ctx->GuestFsBase) ||
        !VmReadChecked(GUEST_GS_BASE, &Ctx->GuestGsBase) ||
        !VmReadChecked(GUEST_EFER, &Ctx->GuestEfer) ||
        !VmReadChecked(GUEST_PAT, &Ctx->GuestPat) ||
        !VmReadChecked(GUEST_SYSENTER_CS, &Ctx->GuestSysenterCs) ||
        !VmReadChecked(GUEST_SYSENTER_ESP, &Ctx->GuestSysenterEsp) ||
        !VmReadChecked(GUEST_SYSENTER_EIP, &Ctx->GuestSysenterEip) ||
        !VmReadChecked(GUEST_DR7, &Ctx->GuestDr7) ||
         !VmReadChecked(GUEST_DEBUGCTL, &Ctx->GuestDebugctl) ||
         !VmReadChecked(EXIT_QUALIFICATION, &vcpu->LastExitQualification)) {
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }
    SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityExitQualification);
    u64 guestTr = 0;
    u64 guestCsAr = 0;
    u64 guestSsAr = 0;
    u64 guestTrAr = 0;
    if (!VmReadChecked(GUEST_TR_SELECTOR, &guestTr) ||
        !VmReadChecked(GUEST_CS_AR_BYTES, &guestCsAr) ||
        !VmReadChecked(GUEST_SS_AR_BYTES, &guestSsAr) ||
        !VmReadChecked(GUEST_TR_AR_BYTES, &guestTrAr)) {
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }
    vcpu->GuestDr7 = Ctx->GuestDr7;
    vcpu->GuestDebugctl = Ctx->GuestDebugctl;
    vcpu->LastGuestCr0 = Ctx->GuestCr0;
    vcpu->LastGuestCr3 = Ctx->GuestCr3;
    vcpu->LastGuestCr4 = Ctx->GuestCr4;
    vcpu->LastGuestCs = Ctx->GuestCs;
    vcpu->LastGuestSs = Ctx->GuestSs;
    vcpu->LastGuestTr = guestTr;
    vcpu->LastGuestCsAr = static_cast<u32>(guestCsAr);
    vcpu->LastGuestSsAr = static_cast<u32>(guestSsAr);
    vcpu->LastGuestTrAr = static_cast<u32>(guestTrAr);
    vcpu->LastGuestDr7 = Ctx->GuestDr7;
    vcpu->LastGuestDebugctl = Ctx->GuestDebugctl;
    vcpu->LastGuestEfer = Ctx->GuestEfer;
    vcpu->LastGuestPat = Ctx->GuestPat;
    vcpu->LastGuestRip = Ctx->GuestRip;
    vcpu->LastGuestRsp = Ctx->GuestRsp;
    vcpu->LastRflags = Ctx->Rflags;
    if (g_CetVmcsEnabled) {
        if (!VmReadChecked(GUEST_S_CET, &Ctx->GuestSCet) ||
            !VmReadChecked(GUEST_SSP, &Ctx->GuestSsp) ||
            !VmReadChecked(GUEST_INTR_SSP_TABLE,
                           &Ctx->GuestInterruptSspTable)) {
            Ctx->HaltVm = 1;
            vcpu->LastExitAction = kExitActionHalt;
            FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
            return;
        }
    }
    SetVmcsDiagnosticValidity(vcpu, HvVmcsValidityGuestState);
    vcpu->GuestXcr0 = Ctx->GuestXcr0;
    vcpu->LastGuestXcr0 = Ctx->GuestXcr0;
    vcpu->LastGuestXss = Ctx->GuestXss;
    vcpu->LastGuestSCet = Ctx->GuestSCet;
    vcpu->LastGuestSsp = Ctx->GuestSsp;
    vcpu->LastGuestInterruptSspTable = Ctx->GuestInterruptSspTable;
    // IA32_KERNEL_GS_BASE is not represented in the VMCS.  The VM-exit
    // assembly stub snapshots the guest value before restoring the host
    // per-CPU value; copy that snapshot into the teardown context so the
    // validity checks and VMXOFF/IRET path can restore it exactly.
    // (The field is already populated at CTX_GUEST_KGS by arch.asm.)

    // SWAPGS does not cause a VM-exit and IA32_KERNEL_GS_BASE is not loaded
    // from VMCS on VM-entry/exit. The assembly snapshot is authoritative for
    // the guest KGS value; do not infer SWAPGS parity from an old GS/KGS pair.
    if (g_XsavesEnabled) {
        // live state is validated against the immutable save frame. Guest MSR
        // write policy is enforced separately by the WRMSR exit handler
        if ((Ctx->GuestXss & ~g_XsavesMask) != 0) {
            WriteHvTrace(vcpu, cpuId, HvTraceEventXssPreservationFail,
                         Ctx->GuestXss, g_XsavesMask,
                         g_GuestXssWriteMask, g_HostXssMask);
            vcpu->LastExitAction = kExitActionHalt;
            Ctx->HaltVm = 1;
            FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
            return;
        }
        vcpu->GuestXss = Ctx->GuestXss;
    }
    vcpu->GuestGsBase = Ctx->GuestGsBase;
    vcpu->GuestKernelGsBase = Ctx->GuestKernelGsBase;

    if (ShouldInjectFault(cpuId, HvFaultLateVmEntry) ||
        ShouldInjectFault(cpuId, HvFaultFirstVmexit)) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventVmEntryFailure,
                     static_cast<u64>(HvFaultLateVmEntry));
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }

    // Intel defines VM_EXIT_INSTRUCTION_LEN as a byte count in the range
    // 1..15 for the exits that this handler advances.  A zero or oversized
    // value would otherwise replay the same instruction forever or move RIP
    // into an untrusted address.  Stop on the private VMX stack with the
    // complete diagnostic record still intact.
    const bool requiresRipAdvance =
        ExitReason == VM_EXIT_REASON_CPUID ||
        ExitReason == VM_EXIT_REASON_VMCALL ||
        ExitReason == VM_EXIT_REASON_RDMSR ||
        ExitReason == VM_EXIT_REASON_WRMSR ||
        ExitReason == VM_EXIT_REASON_CR_ACCESS ||
        ExitReason == VM_EXIT_REASON_XSETBV;
    if (requiresRipAdvance &&
        (ExitLen == 0 || ExitLen > 15 || !IsCanonical(Ctx->GuestRip))) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventContractFail,
                     rawExitReason, ExitLen, Ctx->GuestRip,
                     vcpu->LastExitQualification);
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
        return;
    }

    bool AdvanceRip = true;

    switch (ExitReason) {
        case VM_EXIT_REASON_CPUID: // CPUID
        {
            const u32 leaf = static_cast<u32>(Ctx->Rax);
            const u32 subleaf = static_cast<u32>(Ctx->Rcx);
            const bool userProbeRequest =
                kEnableUserCpuidProbe && leaf == kUserProbeLeaf &&
                subleaf == kUserProbeSubleaf;
            if (userProbeRequest) {
                Ctx->Rax = kUserProbeSignatureEax;
                Ctx->Rbx = cpuId;
                Ctx->Rcx = static_cast<u32>(InterlockedCompareExchange(
                    &vcpu->VmExitCount, 0, 0));
                Ctx->Rdx = kUserProbeSignatureEdx;
                break;
            }

            const bool firstExitProbeRequest =
                leaf == kFirstExitProbeLeaf && subleaf == 0;
            if (firstExitProbeRequest) {
                MarkFirstExitProbeVmExitEntered(vcpu, cpuId, basicExitReason);
            }
            const long probeState = ReadFirstExitProbeState(vcpu);
            const bool firstExitProbeResponse =
                firstExitProbeRequest &&
                (probeState == FirstExitProbeArmed ||
                 probeState == FirstExitProbeVmExitEntered);
            if (firstExitProbeResponse) {
                Ctx->Rax = kFirstExitProbeLeaf;
                Ctx->Rbx = kFirstExitProbeEbx;
                Ctx->Rcx = kFirstExitProbeEcx;
                Ctx->Rdx = kFirstExitProbeEdx;
            }
            else {
                // Late launch must not renegotiate CPU capabilities after
                // Windows has already initialized CET, XSTATE and PT. Run
                // the requested leaf natively so virtualized processors and
                // the temporarily native coordinator expose one coherent view.
                int regs[4] = {};
                __cpuidex(regs, static_cast<int>(leaf),
                          static_cast<int>(subleaf));

                // CPUID writes 32-bit outputs and zero-extends them in
                // 64-bit mode. Avoid sign extension from int.
                Ctx->Rax = static_cast<u32>(regs[0]);
                Ctx->Rbx = static_cast<u32>(regs[1]);
                Ctx->Rcx = static_cast<u32>(regs[2]);
                Ctx->Rdx = static_cast<u32>(regs[3]);
            }
            break;
        }

        case VM_EXIT_REASON_VMCALL: // VMCALL
            AdvanceRip = HandleVmCall(Ctx);
            break;

        case VM_EXIT_REASON_RDMSR: // RDMSR
            AdvanceRip = HandleMsrRead(Ctx);
            break;

        case VM_EXIT_REASON_WRMSR: // WRMSR
            AdvanceRip = HandleMsrWrite(Ctx);
            break;

        case VM_EXIT_REASON_CR_ACCESS: // control-register access
            AdvanceRip = HandleCrAccess(Ctx);
            break;

        case VM_EXIT_REASON_RDPMC:
        case VM_EXIT_REASON_RDTSC:
            // These controls are rejected during VMCS setup. Seeing either
            // reason means a capability mismatch or stale VMCS enabled an
            // instruction exit without an emulation path.
            WriteHvTrace(vcpu, cpuId, HvTraceEventContractFail,
                         rawExitReason, ExitLen, Ctx->GuestRip,
                         vcpu->LastExitQualification);
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_GETSEC:
        case VM_EXIT_REASON_INVD:
        case VM_EXIT_REASON_INVEPT:
        case VM_EXIT_REASON_INVVPID:
        case VM_EXIT_REASON_VMCLEAR:
        case VM_EXIT_REASON_VMLAUNCH:
        case VM_EXIT_REASON_VMPTRLD:
        case VM_EXIT_REASON_VMPTRST:
        case VM_EXIT_REASON_VMREAD:
        case VM_EXIT_REASON_VMWRITE:
        case VM_EXIT_REASON_VMRESUME:
        case VM_EXIT_REASON_VMXOFF:
        case VM_EXIT_REASON_VMXON:
            // HyperDbg treats these unconditional non-root exits as unsupported
            // instructions. Inject #UD at the original RIP instead of parking
            // a processor on an instruction this monitor does not emulate.
            InjectGuestException(Ctx, 6, false);
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_XSETBV:
            AdvanceRip = HandleXsetbv(Ctx, vcpu);
            break;

        case VM_EXIT_REASON_XSAVES:
        case VM_EXIT_REASON_XRSTORS:
            // This exit is outside the published instruction contract. Keep
            // the VMCS available to the fatal path instead of guessing that
            // the interrupted instruction is safe to execute natively.
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_EXTERNAL_INTERRUPT: // external interrupt
            // SetupVmcs rejects every pin-based interrupt-exit control.  If
            // this reason is nevertheless observed (for example after a
            // firmware/VMX capability mismatch), leave VMX and let the host
            // execute the interrupted context natively.
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_TRIPLE_FAULT: // triple fault
        case VM_EXIT_REASON_INVALID_GUEST_STATE: // invalid guest state
            // Neither exit has an architectural continuation. Freeze the
            // current VMCS before the assembly fatal path attempts VMXOFF, so the
            // first fatal guest state is copied into the crash snapshot.
            WriteHvTrace(vcpu, cpuId, HvTraceEventFatalVmexit,
                         rawExitReason, static_cast<u64>(exitCount),
                         Ctx->GuestRip, Ctx->GuestRsp);
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            AdvanceRip = false;
            break;

        case 0: // exception or NMI
            // The setup path exits on guest #DF before hardware attempts a
            // third fault. Keep the full event snapshot and halt on the
            // private VMX stack instead of attempting native continuation.
            if ((exitIntrInfo & VM_ENTRY_INTR_INFO_VALID) != 0 &&
                (exitIntrInfo & 0xFFU) == VMX_EXCEPTION_VECTOR_DOUBLE_FAULT) {
                WriteHvTrace(vcpu, cpuId, HvTraceEventFatalVmexit,
                             rawExitReason, static_cast<u64>(exitCount),
                             exitIntrInfo, idtVectoringInfo);
                Ctx->AbortVm = 0;
                Ctx->HaltVm = 1;
                AdvanceRip = false;
                break;
            }
            [[fallthrough]];
        default:
            // These exits are not requested by our control bitmap.  There is
            // no generic emulation is available, so leave VMX and execute the
            // interrupted kernel context natively instead of looping in VMX.
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            AdvanceRip = false;
            break;
    }

    // WRMSR handlers may have changed either half of the guest GS pair.  Do
    // not leave the per-CPU shadow at the pre-exit values: the next VM-exit's
    // SWAPGS parity check would mistake the legitimate write for corrupted
    // KERNEL_GS_BASE and park the processor.
    if (!Ctx->HaltVm) {
        vcpu->GuestGsBase = Ctx->GuestGsBase;
        vcpu->GuestKernelGsBase = Ctx->GuestKernelGsBase;
    }

    // The unload VMCALL intentionally skips its instruction.  Other aborts
    // are never generated by the emulation paths; keep this guard for a
    // malformed context rather than resuming it.
    if (Ctx->AbortVm && ExitReason != VM_EXIT_REASON_VMCALL) {
        AdvanceRip = false;
    }

    if (AdvanceRip && ExitLen != 0 && IsCanonical(Ctx->GuestRip)) {
        const u64 nextRip = Ctx->GuestRip + ExitLen;
        if (!IsCanonical(nextRip) || nextRip < Ctx->GuestRip) {
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            vcpu->LastExitAction = kExitActionHalt;
            FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
            return;
        }
        Ctx->GuestRip = nextRip;
        if (!VmWriteChecked(GUEST_RIP, nextRip)) {
            // A failed VMWRITE leaves the VMCS/software RIP pair
            // inconsistent.  Do not attempt VMRESUME with partially updated
            // guest state; the assembly epilogue will take the park path.
            Ctx->AbortVm = 0;
            Ctx->HaltVm = 1;
            vcpu->LastExitAction = kExitActionHalt;
            FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
            return;
        }
    }

    const u32 id = CurrentProcessorIndex();
    if (g_VcpuData && id < g_ProcessorCount &&
        (InterlockedCompareExchange(&g_VcpuData[id].VmcsWriteFailed, 0, 0) != 0 ||
         InterlockedCompareExchange(&g_VcpuData[id].VmcsReadFailed, 0, 0) != 0)) {
        // A failed VMCS access means the software context is not trustworthy.
        // Never attempt VMRESUME with partially updated state.
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
    }

    if (Ctx->HaltVm) {
        vcpu->LastExitAction = kExitActionHalt;
    } else if (Ctx->AbortVm) {
        vcpu->LastExitAction = kExitActionAbort;
    } else if (AdvanceRip) {
        vcpu->LastExitAction = kExitActionResume;
    } else {
        vcpu->LastExitAction = kExitActionInject;
    }
    if (ShouldInjectFault(cpuId, HvFaultBeforeVmresume) ||
        ShouldInjectFault(cpuId, HvFaultVmresumeFailure)) {
        WriteHvTrace(vcpu, cpuId, HvTraceEventPreVmresume,
                     static_cast<u64>(HvFaultBeforeVmresume));
        Ctx->AbortVm = 0;
        Ctx->HaltVm = 1;
        vcpu->LastExitAction = kExitActionHalt;
    }
    if (Ctx->HaltVm || Ctx->AbortVm) {
        FailFirstExitProbeAtFatalBoundary(vcpu, cpuId);
    }
    CompleteFirstExitProbe(vcpu, cpuId);
    if (!Ctx->HaltVm && !Ctx->AbortVm) {
        InterlockedIncrement(&vcpu->VmResumeAttempts);
    }
}

// ==============================================================================
// VMCS Setup
// ==============================================================================

// extract the 64-bit base address from a 16-byte tss descriptor
u64 GetTssBase(const u64 GdtBase, const u16 GdtLimit, const u16 Selector) {
    const u64 offset = Selector & 0xFFF8U;
    if ((Selector & 0x7U) != 0 || offset == 0 || offset > GdtLimit ||
        GdtLimit - offset < 15U || !IsCanonical(GdtBase) ||
        !IsCanonical(GdtBase + offset)) {
        return 0;
    }
    auto descriptor = reinterpret_cast<u8*>(GdtBase + offset);
    const u8 access = descriptor[5];
    const u8 type = access & 0x0FU;
    // A long-mode TSS is a present available (9) or busy (B) system
    // descriptor. Rejecting all other types prevents a malformed TR from
    // producing an invalid HOST_TR_BASE during VM-entry.
    if ((access & 0x80U) == 0 || (type != 9U && type != 0xBU)) return 0;

    u64 base = 0;
    base |= static_cast<u64>(descriptor[2]);
    base |= static_cast<u64>(descriptor[3]) << 8;
    base |= static_cast<u64>(descriptor[4]) << 16;

    base |= static_cast<u64>(static_cast<u32>(descriptor[7])) << 24;
    u32 highPart = 0;
    RtlCopyMemory(&highPart, &descriptor[8], sizeof(highPart));
    const u64 high = highPart;
    base |= (high << 32);

    return IsCanonical(base) ? base : 0;
}

// initialize the vmcs for a single virtual cpu
bool SetupVmcs(const VcpuContext* Vcpu, void* GuestSp, void* GuestIp) {
    if (!Vcpu) return false;
    VcpuContext* mutableVcpu = const_cast<VcpuContext*>(Vcpu);
    // invalidate the previous tuple before sampling the new VMCS boundary
    mutableVcpu->LaunchCr3Metadata = 0;
    InterlockedExchange(&mutableVcpu->LaunchDescriptorRejectMask, 0);
    mutableVcpu->LaunchDescriptorSelectorsLow = 0;
    mutableVcpu->LaunchDescriptorSelectorsHigh = 0;
    mutableVcpu->LaunchDescriptorGdtBase = 0;
    mutableVcpu->LaunchDescriptorIdtBase = 0;
    mutableVcpu->LaunchDescriptorTssBase = 0;
    InterlockedExchange(&mutableVcpu->FatalSnapshotCommitState,
                        HvFatalSnapshotEmpty);
    InterlockedExchange(&mutableVcpu->NativeTeardownRejectMask,
                        static_cast<LONG>(HvNativeTeardownRejectNone));
    InterlockedExchange(&mutableVcpu->TeardownRequest, 0);
    InterlockedExchange(&mutableVcpu->LastEventSnapshotValid, 0);
    InterlockedExchange(&mutableVcpu->VmcsWriteFailed, 0);
    InterlockedExchange(&mutableVcpu->VmcsWriteState, 0);
    InterlockedExchange(&mutableVcpu->VmcsReadFailed, 0);
    InterlockedExchange(&mutableVcpu->VmcsReadState, 0);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(
                              &mutableVcpu->VmcsDiagnosticValidity),
                          static_cast<LONG64>(HvVmcsValidityNone));
    InterlockedExchange(&mutableVcpu->VmcsValueMismatch, 0);
    InterlockedExchange(&mutableVcpu->VmcsMismatchState, 0);
    mutableVcpu->FirstVmcsWriteField = 0;
    mutableVcpu->FirstVmcsWriteFlags = 0;
    mutableVcpu->FirstVmcsWriteError = 0;
    mutableVcpu->FirstVmcsReadField = 0;
    mutableVcpu->FirstVmcsReadFlags = 0;
    mutableVcpu->FirstVmcsReadError = 0;
    mutableVcpu->FirstVmcsMismatchField = 0;
    mutableVcpu->FirstVmcsMismatchExpected = 0;
    mutableVcpu->FirstVmcsMismatchActual = 0;
    mutableVcpu->FirstVmcsMismatchMask = 0;
    mutableVcpu->PrimaryControlsCapability = 0;
    mutableVcpu->TertiaryControlsAllowed = 0;
    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseDescriptors);
    const u32 cpuId = CurrentProcessorIndex();
    HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup begin: vmxon_pa=0x%llX "
                     "vmcs_pa=0x%llX msr_bitmap_pa=0x%llX host_cr3=0x%llX "
                     "host_rsp=0x%llX\n", cpuId, Vcpu->VmxOnPhys,
                     Vcpu->VmcsPhys, Vcpu->MsrBitmapPhys, Vcpu->HostCr3,
                     Vcpu->HostStackTop);

    const u64 gdtBase = GetGdtBase();
    const u16 gdtLimit = GetGdtLimit();
    const u64 idtBase = GetIdtBase();
    const u16 idtLimit = GetIdtLimit();
    const u16 trSelector = GetTr();
    const u16 ldtrSelector = GetLdtr();
    const u64 tssBase = GetTssBase(gdtBase, gdtLimit, trSelector);

    const u16 csSelector = GetCs();
    const u16 ssSelector = GetSs();
    const u16 dsSelector = GetDs();
    const u16 esSelector = GetEs();
    const u16 fsSelector = GetFs();
    const u16 gsSelector = GetGs();
    const u64 hostCr0 = __readcr0();
    const u64 hostCr4 = __readcr4();
    const u64 guestCr0 = AdjustCr0(hostCr0);
    const u64 guestCr4 = AdjustCr4(hostCr4);
    const u64 rawHostCr3 = Vcpu->HostCr3;
    const u64 rawGuestCr3 = __readcr3();
    const u64 hostCr3 = NormalizeCr3(rawHostCr3, hostCr4);
    const u64 guestCr3 = NormalizeCr3(rawGuestCr3, guestCr4);
    const u64 launchCr3Metadata =
        PackLaunchCr3Metadata(rawGuestCr3, rawHostCr3, guestCr4, hostCr4);
    mutableVcpu->LaunchRawGuestCr3 = rawGuestCr3;
    mutableVcpu->LaunchGuestCr3 = guestCr3;
    mutableVcpu->LaunchRawHostCr3 = rawHostCr3;
    mutableVcpu->LaunchHostCr3 = hostCr3;
    MemoryBarrier();
    mutableVcpu->LaunchCr3Metadata = launchCr3Metadata;
    WriteHvTrace(mutableVcpu, cpuId, HvTraceEventCr3LaunchContract,
                 rawGuestCr3, guestCr3, rawHostCr3, launchCr3Metadata);
    const bool hostCetWriteProtectValid =
        (hostCr4 & CR4_CET) == 0 || (hostCr0 & kCr0WriteProtect) != 0;
    const bool guestCetWriteProtectValid =
        (guestCr4 & CR4_CET) == 0 || (guestCr0 & kCr0WriteProtect) != 0;
    if (!hostCetWriteProtectValid || !guestCetWriteProtectValid) {
        WriteHvTrace(mutableVcpu, cpuId, HvTraceEventContractFail,
                     hostCr0, hostCr4, guestCr0, guestCr4);
        HV_VERBOSE_PRINT(
            "[HV] CPU %u VMCS setup rejected CET without CR0.WP: "
            "host_cr0=0x%llX host_cr4=0x%llX guest_cr0=0x%llX "
            "guest_cr4=0x%llX\n",
            cpuId, hostCr0, hostCr4, guestCr0, guestCr4);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureCetWriteProtect,
                           hostCr0, hostCr4);
        return false;
    }
    // Capture all VMX-managed MSRs once on the owning logical processor. A
    // second read later in this function could observe a context switch or a
    // concurrent kernel update and produce a host/guest pair that never
    // existed architecturally.
    u64 fsBase = 0;
    u64 gsBase = 0;
    u64 hostEfer = 0;
    u64 pat = 0;
    u64 sysenterCs = 0;
    u64 sysenterEsp = 0;
    u64 sysenterEip = 0;
    const bool msrSnapshotValid =
        ReadMsrSafe(MSR_FS_BASE, &fsBase) &&
        ReadMsrSafe(MSR_GS_BASE, &gsBase) &&
        ReadMsrSafe(MSR_IA32_EFER, &hostEfer) &&
        ReadMsrSafe(MSR_IA32_PAT, &pat) &&
        ReadMsrSafe(MSR_IA32_SYSENTER_CS, &sysenterCs) &&
        ReadMsrSafe(MSR_IA32_SYSENTER_ESP, &sysenterEsp) &&
        ReadMsrSafe(MSR_IA32_SYSENTER_EIP, &sysenterEip);
    const bool msrSnapshotUsable =
        msrSnapshotValid && IsCanonical(fsBase) && IsCanonical(gsBase) &&
        sysenterCs <= 0xFFFFULL && IsCanonical(sysenterEsp) &&
        IsCanonical(sysenterEip) && IsValidIa32eEfer(hostEfer, hostCr0) &&
        IsValidPatValue(pat);
    if (!msrSnapshotUsable) {
        WriteHvTrace(mutableVcpu, cpuId, HvTraceEventContractFail, hostEfer,
                     pat, fsBase, gsBase);
        HV_VERBOSE_PRINT(
            "[HV] CPU %u VMCS setup rejected MSR state: valid=%u "
            "efer=0x%llX pat=0x%llX fs=0x%llX gs=0x%llX "
            "sysenter_cs=0x%llX sysenter_esp=0x%llX sysenter_eip=0x%llX\n",
            cpuId, msrSnapshotUsable ? 1U : 0U, hostEfer, pat, fsBase, gsBase,
            sysenterCs, sysenterEsp, sysenterEip);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureMsrSnapshot,
                           hostEfer, pat);
        return false;
    }
    const u64 guestEfer = hostEfer;
    const u64 guestPat = pat;
    const bool guestTrUsable =
        IsGuestTrSelectorUsable(gdtBase, gdtLimit, trSelector);

    if (!guestTrUsable) {
        HV_VERBOSE_PRINT(
            "[HV] CPU %u VMCS setup rejected guest TR 0x%04X: "
            "IA-32e guest requires a present busy 64-bit TSS (type=0xB)\n",
            cpuId, trSelector);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureGuestTr,
                           trSelector, tssBase);
        return false;
    }

    u32 descriptorRejectMask = HvLaunchDescriptorRejectNone;
    if (!IsCanonical(gdtBase))
        descriptorRejectMask |= HvLaunchDescriptorRejectGdtBase;
    if (!IsCanonical(idtBase))
        descriptorRejectMask |= HvLaunchDescriptorRejectIdtBase;
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, csSelector, false, false, true,
                             true, false))
        descriptorRejectMask |= HvLaunchDescriptorRejectCs;
    // In IA-32e mode a null SS selector is legal when the VMCS access-rights
    // field marks SS unusable. Intel applies SS type/present checks only to a
    // usable SS, and HyperDbg follows the same rule by setting AR.Unusable for
    // selector 0. HvGetSegmentAr(0) below already returns 0x10000.
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, ssSelector, true, false, false,
                             true, true))
        descriptorRejectMask |= HvLaunchDescriptorRejectSs;
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, dsSelector, true, false, false,
                             false, false))
        descriptorRejectMask |= HvLaunchDescriptorRejectDs;
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, esSelector, true, false, false,
                             false, false))
        descriptorRejectMask |= HvLaunchDescriptorRejectEs;
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, fsSelector, true, false, false,
                             false, false))
        descriptorRejectMask |= HvLaunchDescriptorRejectFs;
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, gsSelector, true, false, false,
                             false, false))
        descriptorRejectMask |= HvLaunchDescriptorRejectGs;
    if (ldtrSelector != 0 &&
        !IsGdtSelectorUsable(gdtBase, gdtLimit, ldtrSelector, false, true,
                             false, true, false))
        descriptorRejectMask |= HvLaunchDescriptorRejectLdtr;
    if (!IsValidArchitecturalCr3(hostCr3, hostCr4))
        descriptorRejectMask |= HvLaunchDescriptorRejectHostCr3;
    if (!IsValidArchitecturalCr3(guestCr3, guestCr4))
        descriptorRejectMask |= HvLaunchDescriptorRejectGuestCr3;
    if (tssBase == 0)
        descriptorRejectMask |= HvLaunchDescriptorRejectTssBase;

    mutableVcpu->LaunchDescriptorSelectorsLow =
        PackSegmentSelectors(csSelector, ssSelector, dsSelector, esSelector);
    mutableVcpu->LaunchDescriptorSelectorsHigh =
        PackSegmentSelectors(fsSelector, gsSelector, ldtrSelector, trSelector);
    mutableVcpu->LaunchDescriptorGdtBase = gdtBase;
    mutableVcpu->LaunchDescriptorIdtBase = idtBase;
    mutableVcpu->LaunchDescriptorTssBase = tssBase;
    InterlockedExchange(&mutableVcpu->LaunchDescriptorRejectMask,
                        static_cast<LONG>(descriptorRejectMask));

    if (descriptorRejectMask != HvLaunchDescriptorRejectNone) {
        WriteHvTrace(mutableVcpu, cpuId, HvTraceEventDescriptorReject,
                     descriptorRejectMask,
                     mutableVcpu->LaunchDescriptorSelectorsLow,
                     mutableVcpu->LaunchDescriptorSelectorsHigh, guestCr3);
        HV_VERBOSE_PRINT(
            "[HV] CPU %u VMCS descriptor preflight rejected: mask=0x%X "
            "gdt=0x%llX/0x%X idt=0x%llX/0x%X tss=0x%llX "
            "selectors=0x%llX/0x%llX guest_cr3=0x%llX host_cr3=0x%llX\n",
            cpuId, descriptorRejectMask, gdtBase, gdtLimit, idtBase, idtLimit,
            tssBase, mutableVcpu->LaunchDescriptorSelectorsLow,
            mutableVcpu->LaunchDescriptorSelectorsHigh, guestCr3, hostCr3);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureDescriptorCr3,
                           descriptorRejectMask,
                           mutableVcpu->LaunchDescriptorSelectorsLow);
        return false;
    }

    // The current guest-state builder does not decode an LDT descriptor base.
    // Refuse a non-empty LDTR instead of writing a guessed base and letting
    // VMLAUNCH fail with invalid guest state
    if (ldtrSelector != 0) {
        HV_VERBOSE_PRINT("[HV] VMCS setup rejected a non-empty LDTR 0x%04X\n",
                         ldtrSelector);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureLdtr,
                           ldtrSelector, 0);
        return false;
    }

    // LAR/LSL are sampled together with the selectors. Keep the exact values
    // used for VMCS writes and readback comparisons; reissuing them later can
    // silently compare a different descriptor image after a GDT update.
    const u32 csLimit = HvGetSegmentLimit(csSelector);
    const u32 ssLimit = HvGetSegmentLimit(ssSelector);
    const u32 dsLimit = HvGetSegmentLimit(dsSelector);
    const u32 esLimit = HvGetSegmentLimit(esSelector);
    const u32 fsLimit = HvGetSegmentLimit(fsSelector);
    const u32 gsLimit = HvGetSegmentLimit(gsSelector);
    const u32 ldtrLimit = HvGetSegmentLimit(ldtrSelector);
    const u32 trLimit = HvGetSegmentLimit(trSelector);
    const u32 csAr = HvGetSegmentAr(csSelector);
    const u32 ssAr = HvGetSegmentAr(ssSelector);
    const u32 dsAr = HvGetSegmentAr(dsSelector);
    const u32 esAr = HvGetSegmentAr(esSelector);
    const u32 fsAr = HvGetSegmentAr(fsSelector);
    const u32 gsAr = HvGetSegmentAr(gsSelector);
    const u32 ldtrAr = HvGetSegmentAr(ldtrSelector);
    const u32 trAr = HvGetSegmentAr(trSelector);
    if ((trAr & 0x10000U) != 0 || trLimit == 0) {
        WriteHvTrace(mutableVcpu, cpuId, HvTraceEventContractFail, trSelector,
                     trLimit, trAr, tssBase);
        HV_VERBOSE_PRINT(
            "[HV] CPU %u VMCS setup rejected sampled guest TR: "
            "selector=0x%04X limit=0x%X ar=0x%X base=0x%llX\n",
            cpuId, trSelector, trLimit, trAr, tssBase);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureSampledTr,
                           trLimit, trAr);
        return false;
    }

    if (!PrepareVmxHostIdt(mutableVcpu, idtBase, idtLimit, cpuId)) {
        WriteHvTrace(mutableVcpu, cpuId, HvTraceEventContractFail,
                     idtBase, idtLimit, mutableVcpu->VmxHostIdtBase, 0);
        HV_VERBOSE_PRINT(
            "[HV] CPU %u VMCS setup rejected private host IDT: "
            "native=0x%llX/0x%X private=0x%llX\n",
            cpuId, idtBase, idtLimit, mutableVcpu->VmxHostIdtBase);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureDescriptorCr3,
                           idtBase, mutableVcpu->VmxHostIdtBase);
        return false;
    }
    const u64 vmxHostIdtBase = mutableVcpu->VmxHostIdtBase;

    mutableVcpu->HostSegmentSelectorsLow =
        PackSegmentSelectors(csSelector, ssSelector, dsSelector, esSelector);
    mutableVcpu->HostSegmentSelectorsHigh =
        PackSegmentSelectors(fsSelector, gsSelector, ldtrSelector, trSelector);
    mutableVcpu->HostGdtBase = gdtBase;
    mutableVcpu->HostIdtBase = idtBase;
    mutableVcpu->HostTrBase = tssBase;
    mutableVcpu->HostGdtLimit = gdtLimit;
    mutableVcpu->HostIdtLimit = idtLimit;
    mutableVcpu->HostTrLimit = trLimit;
    mutableVcpu->HostTrAr = trAr;
    mutableVcpu->HostCsLimit = csLimit;
    mutableVcpu->HostSsLimit = ssLimit;
    mutableVcpu->HostCsAr = csAr;
    mutableVcpu->HostSsAr = ssAr;
    InterlockedExchange(&mutableVcpu->NativeTeardownSafe, 1);

    // ==============================================================================
    // Host State Configuration
    // ==============================================================================
    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseHostState);
    if (!VmWriteChecked(HOST_CR0, hostCr0) ||
        !VmWriteChecked(HOST_CR3, hostCr3) ||
        !VmWriteChecked(HOST_CR4, hostCr4)) {
        return false;
    }

    // host selectors
    VmWriteChecked(HOST_CS_SELECTOR, csSelector & 0xFFF8);
    VmWriteChecked(HOST_SS_SELECTOR, ssSelector & 0xFFF8);
    VmWriteChecked(HOST_DS_SELECTOR, dsSelector & 0xFFF8);
    VmWriteChecked(HOST_ES_SELECTOR, esSelector & 0xFFF8);
    VmWriteChecked(HOST_FS_SELECTOR, fsSelector & 0xFFF8);
    VmWriteChecked(HOST_GS_SELECTOR, gsSelector & 0xFFF8);
    VmWriteChecked(HOST_TR_SELECTOR, trSelector & 0xFFF8);

    // host base addresses
    VmWriteChecked(HOST_FS_BASE, fsBase);
    VmWriteChecked(HOST_GS_BASE, gsBase);
    VmWriteChecked(HOST_EFER, hostEfer);
    VmWriteChecked(HOST_TR_BASE, tssBase);
    VmWriteChecked(HOST_GDTR_BASE, gdtBase);
    VmWriteChecked(HOST_IDTR_BASE, vmxHostIdtBase);

    // host sysenter
    VmWriteChecked(HOST_IA32_SYSENTER_CS, sysenterCs);
    VmWriteChecked(HOST_IA32_SYSENTER_ESP, sysenterEsp);
    VmWriteChecked(HOST_IA32_SYSENTER_EIP, sysenterEip);

    // host RIP/RSP (exit handler)
    VmWriteChecked(HOST_RSP, Vcpu->HostStackTop);
    VmWriteChecked(HOST_RIP, reinterpret_cast<u64>(HvVmExitEntryPoint));
    if (InterlockedCompareExchange(&mutableVcpu->VmcsWriteFailed, 0, 0) != 0) {
        return false;
    }

    // CET supervisor state is loaded by VM-exit/VM-entry controls rather than
    // by XSAVES.  Keep the host and initial guest copies identical; later
    // guest WRMSR operations update the guest VMCS fields in the exit handler.
    u64 hostSCet = 0;
    u64 hostSsp = 0;
    u64 hostInterruptSspTable = 0;
    if (g_CetVmcsEnabled) {
        hostSCet = __readmsr(MSR_IA32_S_CET);
        hostSsp = __readmsr(MSR_IA32_PL0_SSP);
        hostInterruptSspTable = __readmsr(MSR_IA32_INTERRUPT_SSP_TABLE);
        if (!VmWriteChecked(HOST_S_CET, hostSCet) ||
            !VmWriteChecked(HOST_SSP, hostSsp) ||
            !VmWriteChecked(HOST_INTR_SSP_TABLE, hostInterruptSspTable)) {
            return 0;
        }
    }

    WriteHvTrace(mutableVcpu, cpuId, HvTraceEventVmcsHostDone);
    if (ShouldInjectFault(cpuId, HvFaultAfterHostState)) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureInjected,
                           HvFaultAfterHostState, 0);
        return false;
    }

    // ==============================================================================
    // Guest State Configuration
    // ==============================================================================
    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseGuestState);

    // control registers
    VmWriteChecked(GUEST_CR0, guestCr0);
    VmWriteChecked(GUEST_CR3, guestCr3);
    VmWriteChecked(GUEST_CR4, guestCr4);
    VmWriteChecked(GUEST_DR7, Vcpu->GuestDr7);

    // guest selectors
    VmWriteChecked(GUEST_CS_SELECTOR, csSelector);
    VmWriteChecked(GUEST_SS_SELECTOR, ssSelector);
    VmWriteChecked(GUEST_DS_SELECTOR, dsSelector);
    VmWriteChecked(GUEST_ES_SELECTOR, esSelector);
    VmWriteChecked(GUEST_FS_SELECTOR, fsSelector);
    VmWriteChecked(GUEST_GS_SELECTOR, gsSelector);
    VmWriteChecked(GUEST_LDTR_SELECTOR, ldtrSelector);
    VmWriteChecked(GUEST_TR_SELECTOR, trSelector);

    // guest limits
    VmWriteChecked(GUEST_CS_LIMIT, csLimit);
    VmWriteChecked(GUEST_SS_LIMIT, ssLimit);
    VmWriteChecked(GUEST_DS_LIMIT, dsLimit);
    VmWriteChecked(GUEST_ES_LIMIT, esLimit);
    VmWriteChecked(GUEST_FS_LIMIT, fsLimit);
    VmWriteChecked(GUEST_GS_LIMIT, gsLimit);
    VmWriteChecked(GUEST_LDTR_LIMIT, ldtrLimit);
    VmWriteChecked(GUEST_TR_LIMIT, trLimit);
    VmWriteChecked(GUEST_GDTR_LIMIT, gdtLimit);
    VmWriteChecked(GUEST_IDTR_LIMIT, idtLimit);

    // guest access rights
    VmWriteChecked(GUEST_CS_AR_BYTES, csAr);
    VmWriteChecked(GUEST_SS_AR_BYTES, ssAr);
    VmWriteChecked(GUEST_DS_AR_BYTES, dsAr);
    VmWriteChecked(GUEST_ES_AR_BYTES, esAr);
    VmWriteChecked(GUEST_FS_AR_BYTES, fsAr);
    VmWriteChecked(GUEST_GS_AR_BYTES, gsAr);
    VmWriteChecked(GUEST_LDTR_AR_BYTES, ldtrAr);
    VmWriteChecked(GUEST_TR_AR_BYTES, trAr);

    // guest base addresses
    VmWriteChecked(GUEST_FS_BASE, fsBase);
    VmWriteChecked(GUEST_GS_BASE, gsBase);
    VmWriteChecked(GUEST_GDTR_BASE, gdtBase);
    VmWriteChecked(GUEST_IDTR_BASE, idtBase);

    // flat model bases
    VmWriteChecked(GUEST_CS_BASE, 0);
    VmWriteChecked(GUEST_SS_BASE, 0);
    VmWriteChecked(GUEST_DS_BASE, 0);
    VmWriteChecked(GUEST_ES_BASE, 0);
    VmWriteChecked(GUEST_TR_BASE, tssBase);
    VmWriteChecked(GUEST_LDTR_BASE, 0);

    // guest MSRs
    VmWriteChecked(GUEST_SYSENTER_CS, sysenterCs);
    VmWriteChecked(GUEST_SYSENTER_ESP, sysenterEsp);
    VmWriteChecked(GUEST_SYSENTER_EIP, sysenterEip);
    VmWriteChecked(GUEST_EFER, guestEfer);

    // PAT (Page Attribute Table)
    VmWriteChecked(GUEST_PAT, guestPat);
    VmWriteChecked(HOST_PAT, pat);

    u64 guestSCet = 0;
    u64 guestSsp = 0;
    u64 guestInterruptSspTable = 0;
    if (g_CetVmcsEnabled) {
        guestSCet = __readmsr(MSR_IA32_S_CET);
        guestSsp = __readmsr(MSR_IA32_PL0_SSP);
        guestInterruptSspTable = __readmsr(MSR_IA32_INTERRUPT_SSP_TABLE);
        if (!VmWriteChecked(GUEST_S_CET, guestSCet) ||
            !VmWriteChecked(GUEST_SSP, guestSsp) ||
            !VmWriteChecked(GUEST_INTR_SSP_TABLE, guestInterruptSspTable)) {
            return false;
        }
    }

    // guest execution state
    VmWriteChecked(GUEST_ACTIVITY_STATE, 0); // 0 = Active
    VmWriteChecked(GUEST_INTERRUPTIBILITY_INFO, 0);
    VmWriteChecked(GUEST_VMCS_LINK_PTR, ~0ULL); // Must be -1
    VmWriteChecked(GUEST_DEBUGCTL, Vcpu->GuestDebugctl);
    VmWriteChecked(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    VmWriteChecked(GUEST_SM_BASE, 0);

    // guest RIP/RSP
    // VMX requires canonical guest pointers, not a 16-byte ABI-aligned stack.
    // The launch thunk uses MOVDQU for its XMM frame and restores qwords
    // directly, so a DPC frame that arrives 8-byte aligned remains valid.
    if (!GuestIp || !GuestSp ||
        !IsCanonical(reinterpret_cast<u64>(GuestIp)) ||
        !IsCanonical(reinterpret_cast<u64>(GuestSp))) {
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup rejected guest entry pointers: "
                         "rip=0x%llX rsp=0x%llX\n",
                         cpuId, reinterpret_cast<u64>(GuestIp),
                         reinterpret_cast<u64>(GuestSp));
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureGuestEntry,
                           reinterpret_cast<u64>(GuestIp),
                           reinterpret_cast<u64>(GuestSp));
        return false;
    }
    VmWriteChecked(GUEST_RIP, reinterpret_cast<u64>(GuestIp));
    VmWriteChecked(GUEST_RSP, reinterpret_cast<u64>(GuestSp));
    // HyperDbg restores the DPC's saved flags directly instead of inventing a
    // second IF handoff contract. Keep the live Windows RFLAGS image intact;
    // VM/VIF/VIP must already be clear in the long-mode kernel context
    const u64 callbackRflags = GetRflags();
    constexpr u64 kLongModeInvalidRflags =
        (1ULL << 17) | (1ULL << 19) | (1ULL << 20);
    if ((callbackRflags & kLongModeInvalidRflags) != 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureGuestEntry,
                           callbackRflags, kLongModeInvalidRflags);
        return false;
    }
    const u64 guestRflags = callbackRflags | (1ULL << 1);
    HV_VERBOSE_PRINT("[HV] CPU %u guest launch flags: source=0x%llX "
                     "guest=0x%llX if=%u irql=%u "
                     "guest_sp=0x%llX guest_ip=0x%llX\n", cpuId,
                     callbackRflags, guestRflags,
                     (guestRflags & (1ULL << 9)) != 0 ? 1U : 0U,
                     static_cast<ULONG>(KeGetCurrentIrql()),
                     reinterpret_cast<u64>(GuestSp),
                     reinterpret_cast<u64>(GuestIp));
    if (!VmWriteChecked(GUEST_RFLAGS, guestRflags)) return false;

    WriteHvTrace(mutableVcpu, cpuId, HvTraceEventVmcsGuestDone);
    if (ShouldInjectFault(cpuId, HvFaultAfterGuestState)) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureInjected,
                           HvFaultAfterGuestState, 0);
        return false;
    }

    // ==============================================================================
    // VM Execution Controls
    // ==============================================================================
    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseExecutionControls);

    // match HyperDbg's baseline VMCS image. These fields are inactive in the
    // selected control profile, but explicit zeroes prevent stale values from
    // a reused VMCS from changing the launch contract.
    if (!VmWriteChecked(CONTROL_TSC_OFFSET, 0ULL) ||
        !VmWriteChecked(CONTROL_PAGE_FAULT_ERROR_CODE_MASK, 0ULL) ||
        !VmWriteChecked(CONTROL_PAGE_FAULT_ERROR_CODE_MATCH, 0ULL) ||
        !VmWriteChecked(CONTROL_CR3_TARGET_COUNT, 0ULL) ||
        !VmWriteChecked(CONTROL_VM_EXIT_MSR_STORE_COUNT, 0ULL) ||
        !VmWriteChecked(CONTROL_VM_EXIT_MSR_LOAD_COUNT, 0ULL) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_MSR_LOAD_COUNT, 0ULL)) {
        return false;
    }

    const VmxControlGeneration generation =
        SelectVmxControlGeneration(Vcpu->VmxProfile);
    u32 pinCtlMsr = 0;
    u32 procCtlMsr = 0;
    u32 exitCtlMsr = 0;
    u32 entryCtlMsr = 0;
    switch (generation) {
        case VmxGenerationLegacy:
            pinCtlMsr = MSR_IA32_VMX_PINBASED_CTLS;
            procCtlMsr = MSR_IA32_VMX_PROCBASED_CTLS;
            exitCtlMsr = MSR_IA32_VMX_EXIT_CTLS;
            entryCtlMsr = MSR_IA32_VMX_ENTRY_CTLS;
            break;
        case VmxGenerationTrue:
        case VmxGenerationTrueSecondary:
        case VmxGenerationTrueTertiary:
            pinCtlMsr = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
            procCtlMsr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
            exitCtlMsr = MSR_IA32_VMX_TRUE_EXIT_CTLS;
            entryCtlMsr = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
            break;
        default:
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               static_cast<u64>(generation), 0);
            return false;
    }

    u64 primaryControlsCapability = 0;
    if (!ReadMsrSafe(procCtlMsr, &primaryControlsCapability)) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           procCtlMsr, 0);
        return false;
    }
    mutableVcpu->PrimaryControlsCapability = primaryControlsCapability;

    u32 pinCtl = AdjustControls(0, pinCtlMsr);
    // Intel requires a few reserved pin bits to be one (normally 0x16).
    // Only reject controls that cause exits or require interrupt injection;
    // rejecting the mandatory mask would make VMX fail on mainstream CPUs.
    constexpr u32 pinExitControls = PIN_BASED_EXTERNAL_INTERRUPT_EXITING |
                                     PIN_BASED_NMI_EXITING |
                                     PIN_BASED_VIRTUAL_NMIS |
                                     PIN_BASED_PREEMPTION_TIMER |
                                     PIN_BASED_POSTED_INTERRUPTS;
    const u32 pinMandatoryOn = ControlMandatoryOn(pinCtlMsr);
    if ((pinMandatoryOn & ~VMX_PINBASED_MANDATORY_ON) != 0 ||
        (pinCtl & pinExitControls) != 0 ||
        (pinCtl & ~VMX_PINBASED_MANDATORY_ON) != 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           pinCtl, pinMandatoryOn);
        return false;
    }
    VmWriteChecked(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS, pinCtl);
    // Intercept #DF before the processor reaches the reset-prone third-fault
    // path. The handler records VM_EXIT_INTR_INFO and stops on its own stack.
    VmWriteChecked(CONTROL_EXCEPTION_BITMAP,
                   VMX_EXCEPTION_BITMAP_DOUBLE_FAULT);
    VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0);
    VmWriteChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
    VmWriteChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, 0);

    // Keep the instruction-enable controls in sync with the already-running
    // Windows CPUID contract. Intel specifies #UD in VMX non-root when
    // RDTSCP/INVPCID/XSAVES/WAITPKG are exposed but their corresponding
    // secondary enable control is unavailable. HyperDbg likewise enables the
    // user-wait-and-pause control on its normal VMCS path.
    u32 secondaryRequested = 0;
    const u32 profile = Vcpu->VmxProfile;
    const bool hasSecondaryControls =
        (profile & VmxProfileSecondaryControls) != 0;
    int cpuid7[4] = {};
    __cpuidex(cpuid7, 7, 0);
    const bool guestWaitpkg =
        (static_cast<u32>(cpuid7[2]) & CPUID_7_ECX_WAITPKG) != 0;
    if (hasSecondaryControls) {
        if ((profile & VmxProfileInvpcid) != 0) {
            secondaryRequested |= SECONDARY_ENABLE_INVPCID;
        }
        if ((profile & VmxProfileRdtscp) != 0) {
            secondaryRequested |= SECONDARY_ENABLE_RDTSCP;
        }
    }
    if (guestWaitpkg) {
        if (!hasSecondaryControls ||
            !VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                              SECONDARY_ENABLE_USER_WAIT_PAUSE)) {
            HV_VERBOSE_PRINT(
                "[HV] CPU %u WAITPKG VMCS contract rejected: "
                "CPUID.7.0.ECX[5]=1 secondary=%u allowed=%u\n",
                cpuId, hasSecondaryControls ? 1U : 0U,
                VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                                 SECONDARY_ENABLE_USER_WAIT_PAUSE) ? 1U : 0U);
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               CPUID_7_ECX_WAITPKG,
                               SECONDARY_ENABLE_USER_WAIT_PAUSE);
            return false;
        }
        secondaryRequested |= SECONDARY_ENABLE_USER_WAIT_PAUSE;
    }
    if (g_XsavesEnabled) {
        if (!hasSecondaryControls ||
            (profile & VmxProfileXsaves) == 0) {
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureXstatePolicy,
                               profile, secondaryRequested);
            return false;
        }
        secondaryRequested |= SECONDARY_ENABLE_XSAVES;
    }

    // MSR handling is part of the supported VM-exit contract. CPUID is
    // architecturally intercepted in VMX non-root mode and has no primary
    // control bit; VmExitHandler handles that exit directly.
    u32 requestedPrimary = CPU_BASED_USE_MSR_BITMAPS;
    if (secondaryRequested) requestedPrimary |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    u32 procCtl = AdjustControls(requestedPrimary, procCtlMsr);
    if ((procCtl & CPU_BASED_USE_MSR_BITMAPS) == 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           procCtl, CPU_BASED_USE_MSR_BITMAPS);
        return false;
    }
    if (secondaryRequested &&
        (procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) == 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           procCtl, secondaryRequested);
        return false;
    }
    // Keep the primary control policy explicit. CR3 load/store exiting is
    // controlled by bits 15 and 16, but both exits are reported as the
    // control-register access reason (28). This monitor handles MOV CR3 in
    // HandleCrAccess, including the legacy CPUs that force these bits to one.
    // RDPMC and RDTSC have no enabled emulation path and stay disabled.
    constexpr u32 supportedPrimary =
        CPU_BASED_USE_MSR_BITMAPS |
        CPU_BASED_CR3_LOAD_EXITING |
        CPU_BASED_CR3_STORE_EXITING |
        CPU_BASED_ACTIVATE_TERTIARY_CONTROLS |
        CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    // AdjustControls also applies mandatory-one bits from the capability MSR.
    // The architectural legacy mask includes reserved bits and can differ by
    // generation only for the CR3 load/store controls. Allow that pair as an
    // implemented exit path, while an unknown forced functional control still
    // fails closed instead of creating an unhandled VM-exit loop.
    const u32 primaryMandatoryOn = ControlMandatoryOn(procCtlMsr);
    constexpr u32 knownPrimaryMandatoryOn =
        VMX_PROCBASED_MANDATORY_ON |
        CPU_BASED_CR3_LOAD_EXITING |
        CPU_BASED_CR3_STORE_EXITING;
    if ((primaryMandatoryOn & ~knownPrimaryMandatoryOn) != 0 ||
        (procCtl & ~(supportedPrimary | VMX_PROCBASED_MANDATORY_ON)) != 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           procCtl, primaryMandatoryOn);
        return false;
    }
    constexpr u32 unsupportedPrimary =
        CPU_BASED_INTR_WINDOW_EXITING | CPU_BASED_USE_TSC_OFFSETTING |
        CPU_BASED_HLT_EXITING | CPU_BASED_INVLPG_EXITING |
        CPU_BASED_MWAIT_EXITING | CPU_BASED_RDPMC_EXITING |
        CPU_BASED_RDTSC_EXITING | CPU_BASED_CR8_LOAD_EXITING |
        CPU_BASED_CR8_STORE_EXITING | CPU_BASED_MOV_DR_EXITING |
        CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_USE_IO_BITMAPS |
        CPU_BASED_TPR_SHADOW | CPU_BASED_NMI_WINDOW_EXITING |
        CPU_BASED_MONITOR_TRAP_FLAG | CPU_BASED_MONITOR_EXITING |
        CPU_BASED_PAUSE_EXITING;
    if (procCtl & unsupportedPrimary) {
        HV_VERBOSE_PRINT("[HV] CPU %u VMX primary controls require an "
                         "unsupported exit path: proc=0x%08X mask=0x%08X\n",
                         cpuId, procCtl, procCtl & unsupportedPrimary);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           procCtl, procCtl & unsupportedPrimary);
        return false;
    }
    if (!VmWriteChecked(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, procCtl)) return false;

    u32 secCtl = 0;
    if (procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
        secCtl = AdjustControls(secondaryRequested, MSR_IA32_VMX_PROCBASED_CTLS2);
        if ((secCtl & secondaryRequested) != secondaryRequested) {
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               secCtl, secondaryRequested);
            return false;
        }
        // No EPT/VPID/APIC virtualization/nested controls are implemented.
        // Refuse any mandatory secondary bit outside the exact instruction
        // pass-through set selected from CPUID above.
        if (secCtl & ~secondaryRequested) {
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               secCtl, secondaryRequested);
            return false;
        }
    }
    if ((procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) != 0 &&
        !VmWriteChecked(
            CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            secCtl)) {
        return false;
    }
    HV_VERBOSE_PRINT(
        "[HV] CPU %u secondary instruction contract: cpuid_waitpkg=%u "
        "waitpkg_ctl=%u rdtscp=%u invpcid=%u xsaves=%u sec=0x%08X\n",
        cpuId, guestWaitpkg ? 1U : 0U,
        (secCtl & SECONDARY_ENABLE_USER_WAIT_PAUSE) != 0 ? 1U : 0U,
        (secCtl & SECONDARY_ENABLE_RDTSCP) != 0 ? 1U : 0U,
        (secCtl & SECONDARY_ENABLE_INVPCID) != 0 ? 1U : 0U,
        (secCtl & SECONDARY_ENABLE_XSAVES) != 0 ? 1U : 0U, secCtl);
    InterlockedExchange(&g_HvWaitpkgVmcsEnabled,
                        (secCtl & SECONDARY_ENABLE_USER_WAIT_PAUSE) != 0 ? 1 : 0);

    WriteHvTrace(mutableVcpu, cpuId, HvTraceEventVmcsControlsDone,
                 procCtl, secCtl);
    if (ShouldInjectFault(cpuId, HvFaultAfterVmcsControls)) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureInjected,
                           HvFaultAfterVmcsControls, 0);
        return false;
    }

    // The tertiary capability MSR is a direct 64-bit allowed-one bitmap. Do
    // not apply AdjustControls, whose low half has a different meaning.
    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseTertiaryControls);
    u64 tertiaryCtl = 0;
    if (procCtl & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS) {
        if ((profile & VmxProfileTertiaryControls) == 0) {
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               profile, VmxProfileTertiaryControls);
            return false;
        }
        u64 tertiaryAllowedOne = 0;
        if (!ReadMsrSafe(MSR_IA32_VMX_PROCBASED_CTLS3, &tertiaryAllowedOne)) {
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               MSR_IA32_VMX_PROCBASED_CTLS3, 0);
            return false;
        }
        mutableVcpu->TertiaryControlsAllowed = tertiaryAllowedOne;
        constexpr u64 tertiaryRequested = 0;
        if (!HvTertiaryControlsAllowed(tertiaryRequested,
                                       tertiaryAllowedOne)) {
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               tertiaryRequested, tertiaryAllowedOne);
            return false;
        }
        tertiaryCtl = HvNormalizeTertiaryControls(tertiaryRequested,
                                                  tertiaryAllowedOne);
        if (!VmWriteChecked(
                CONTROL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                tertiaryCtl)) {
            HV_VERBOSE_PRINT("[HV] CPU %u tertiary VMX controls write failed: "
                             "0x%llX\n", cpuId, tertiaryCtl);
            return false;
        }
        HV_VERBOSE_PRINT("[HV] CPU %u tertiary VMX controls: 0x%llX\n",
                         cpuId, tertiaryCtl);
    }

    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseExitEntryControls);

    if (!VmWriteChecked(CONTROL_MSR_BITMAP_ADDRESS, Vcpu->MsrBitmapPhys)) return false;
    if (g_XsavesEnabled &&
        !VmWriteChecked(CONTROL_XSS_EXITING_BITMAP, 0)) {
        return false;
    }

    // Bit 9: Host Address Space Size (Must be 1 for x64 Host)
    u32 requestedExit = VM_EXIT_HOST_ADDRESS_SPACE_SIZE |
                        VM_EXIT_SAVE_DEBUG_CONTROLS |
                        VM_EXIT_SAVE_GUEST_EFER |
                        VM_EXIT_LOAD_HOST_EFER |
                        VM_EXIT_SAVE_GUEST_PAT |
                        VM_EXIT_LOAD_HOST_PAT;
    if (g_CetVmcsEnabled) requestedExit |= VM_EXIT_LOAD_CET_STATE;
    u32 exitCtl = AdjustControls(requestedExit, exitCtlMsr);
    if ((exitCtl & requestedExit) != requestedExit) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           exitCtl, requestedExit);
        return false;
    }
    u32 supportedExit = requestedExit;
    const u32 exitMandatoryOn = ControlMandatoryOn(exitCtlMsr);
    if ((exitMandatoryOn & ~VMX_EXIT_MANDATORY_ON) != 0 ||
        (exitCtl & ~(supportedExit | VMX_EXIT_MANDATORY_ON)) != 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           exitCtl, exitMandatoryOn);
        return false;
    }
    if (!VmWriteChecked(CONTROL_VM_EXIT_CONTROLS, exitCtl)) return false;

    // Bit 9: IA-32e Mode Guest (Must be 1 for x64 Guest)
    u32 requestedEntry = VM_ENTRY_IA32E_MODE_GUEST |
                         VM_ENTRY_LOAD_DEBUG_CONTROLS |
                         VM_ENTRY_LOAD_GUEST_EFER |
                         VM_ENTRY_LOAD_GUEST_PAT;
    if (g_CetVmcsEnabled) requestedEntry |= VM_ENTRY_LOAD_CET_STATE;
    u32 entryCtl = AdjustControls(requestedEntry, entryCtlMsr);
    if ((entryCtl & requestedEntry) != requestedEntry) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           entryCtl, requestedEntry);
        return false;
    }
    u32 supportedEntry = requestedEntry;
    const u32 entryMandatoryOn = ControlMandatoryOn(entryCtlMsr);
    if ((entryMandatoryOn & ~VMX_ENTRY_MANDATORY_ON) != 0 ||
        (entryCtl & ~(supportedEntry | VMX_ENTRY_MANDATORY_ON)) != 0) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                           entryCtl, entryMandatoryOn);
        return false;
    }
    if (!VmWriteChecked(CONTROL_VM_ENTRY_CONTROLS, entryCtl)) return false;

    // Preserve the live Windows CR contract. With both masks zero, the
    // read-shadow fields are inactive and no CR0/CR4 write is synthesized.
    VmWriteChecked(GUEST_CR0, guestCr0);
    VmWriteChecked(GUEST_CR4, guestCr4);

    VmWriteChecked(CONTROL_CR0_GUEST_HOST_MASK, 0ULL);
    VmWriteChecked(CONTROL_CR0_READ_SHADOW, 0ULL);

    const u64 cr4GuestHostMask = GetCr4GuestHostMask();
    const u64 cr4ReadShadow = 0;
    VmWriteChecked(CONTROL_CR4_GUEST_HOST_MASK, cr4GuestHostMask);
    VmWriteChecked(CONTROL_CR4_READ_SHADOW, cr4ReadShadow);

    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseReadback);
    bool success =
        InterlockedCompareExchange(&mutableVcpu->VmcsWriteFailed, 0, 0) == 0;
    bool readbackComplete = false;
    u64 vmcsHostCr0 = 0;
    u64 vmcsHostCr3 = 0;
    u64 vmcsHostCr4 = 0;
    u64 vmcsHostRip = 0;
    u64 vmcsHostRsp = 0;
    u64 vmcsHostCs = 0;
    u64 vmcsHostSs = 0;
    u64 vmcsHostTr = 0;
    u64 vmcsHostFsBase = 0;
    u64 vmcsHostGsBase = 0;
    u64 vmcsHostEfer = 0;
    u64 vmcsHostPat = 0;
    u64 vmcsHostSysenterCs = 0;
    u64 vmcsHostSysenterEsp = 0;
    u64 vmcsHostSysenterEip = 0;
    u64 vmcsHostTrBase = 0;
    u64 vmcsHostGdtBase = 0;
    u64 vmcsHostIdtBase = 0;
    u64 vmcsPinCtl = 0;
    u64 vmcsExceptionBitmap = 0;
    u64 vmcsPrimaryCtl = 0;
    u64 vmcsSecondaryCtl = 0;
    u64 vmcsTertiaryCtl = 0;
    u64 vmcsExitCtl = 0;
    u64 vmcsEntryCtl = 0;
    u64 vmcsMsrBitmap = 0;
    u64 vmcsCr0Mask = 0;
    u64 vmcsCr0Shadow = 0;
    u64 vmcsCr4Mask = 0;
    u64 vmcsCr4Shadow = 0;
    u64 vmcsXssExitingBitmap = 0;
    u64 vmcsGuestCr0 = 0;
    u64 vmcsGuestCr3 = 0;
    u64 vmcsGuestCr4 = 0;
    u64 vmcsGuestRip = 0;
    u64 vmcsGuestRsp = 0;
    u64 vmcsGuestRflags = 0;
    u64 vmcsGuestCs = 0;
    u64 vmcsGuestSs = 0;
    u64 vmcsGuestFsBase = 0;
    u64 vmcsGuestGsBase = 0;
    u64 vmcsGuestEfer = 0;
    u64 vmcsGuestPat = 0;
    u64 vmcsGuestSysenterCs = 0;
    u64 vmcsGuestSysenterEsp = 0;
    u64 vmcsGuestSysenterEip = 0;
    u64 vmcsGuestDebugctl = 0;
    u64 vmcsGuestGdtBase = 0;
    u64 vmcsGuestIdtBase = 0;
    u64 vmcsGuestGdtLimit = 0;
    u64 vmcsGuestIdtLimit = 0;
    u64 vmcsGuestTr = 0;
    u64 vmcsGuestTrLimit = 0;
    u64 vmcsGuestTrAr = 0;
    u64 vmcsGuestTrBase = 0;
    u64 vmcsGuestSCet = 0;
    u64 vmcsGuestSsp = 0;
    u64 vmcsGuestInterruptSspTable = 0;
    if (success) {
        success =
            VmReadChecked(HOST_CR0, &vmcsHostCr0) &&
            VmReadChecked(HOST_CR3, &vmcsHostCr3) &&
            VmReadChecked(HOST_CR4, &vmcsHostCr4) &&
            VmReadChecked(HOST_RIP, &vmcsHostRip) &&
            VmReadChecked(HOST_RSP, &vmcsHostRsp) &&
            VmReadChecked(HOST_CS_SELECTOR, &vmcsHostCs) &&
            VmReadChecked(HOST_SS_SELECTOR, &vmcsHostSs) &&
            VmReadChecked(HOST_TR_SELECTOR, &vmcsHostTr) &&
            VmReadChecked(HOST_FS_BASE, &vmcsHostFsBase) &&
            VmReadChecked(HOST_GS_BASE, &vmcsHostGsBase) &&
            VmReadChecked(HOST_EFER, &vmcsHostEfer) &&
            VmReadChecked(HOST_PAT, &vmcsHostPat) &&
            VmReadChecked(HOST_IA32_SYSENTER_CS, &vmcsHostSysenterCs) &&
            VmReadChecked(HOST_IA32_SYSENTER_ESP, &vmcsHostSysenterEsp) &&
            VmReadChecked(HOST_IA32_SYSENTER_EIP, &vmcsHostSysenterEip) &&
            VmReadChecked(HOST_TR_BASE, &vmcsHostTrBase) &&
            VmReadChecked(HOST_GDTR_BASE, &vmcsHostGdtBase) &&
            VmReadChecked(HOST_IDTR_BASE, &vmcsHostIdtBase) &&
            VmReadChecked(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS,
                          &vmcsPinCtl) &&
            VmReadChecked(CONTROL_EXCEPTION_BITMAP,
                          &vmcsExceptionBitmap) &&
            VmReadChecked(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                          &vmcsPrimaryCtl) &&
            VmReadChecked(CONTROL_VM_EXIT_CONTROLS, &vmcsExitCtl) &&
            VmReadChecked(CONTROL_VM_ENTRY_CONTROLS, &vmcsEntryCtl) &&
            VmReadChecked(CONTROL_MSR_BITMAP_ADDRESS, &vmcsMsrBitmap) &&
            VmReadChecked(CONTROL_CR0_GUEST_HOST_MASK, &vmcsCr0Mask) &&
            VmReadChecked(CONTROL_CR0_READ_SHADOW, &vmcsCr0Shadow) &&
            VmReadChecked(CONTROL_CR4_GUEST_HOST_MASK, &vmcsCr4Mask) &&
            VmReadChecked(CONTROL_CR4_READ_SHADOW, &vmcsCr4Shadow) &&
            VmReadChecked(GUEST_CR0, &vmcsGuestCr0) &&
            VmReadChecked(GUEST_CR3, &vmcsGuestCr3) &&
            VmReadChecked(GUEST_CR4, &vmcsGuestCr4) &&
            VmReadChecked(GUEST_RIP, &vmcsGuestRip) &&
            VmReadChecked(GUEST_RSP, &vmcsGuestRsp) &&
            VmReadChecked(GUEST_RFLAGS, &vmcsGuestRflags) &&
            VmReadChecked(GUEST_CS_SELECTOR, &vmcsGuestCs) &&
            VmReadChecked(GUEST_SS_SELECTOR, &vmcsGuestSs) &&
            VmReadChecked(GUEST_FS_BASE, &vmcsGuestFsBase) &&
            VmReadChecked(GUEST_GS_BASE, &vmcsGuestGsBase) &&
            VmReadChecked(GUEST_EFER, &vmcsGuestEfer) &&
            VmReadChecked(GUEST_PAT, &vmcsGuestPat) &&
            VmReadChecked(GUEST_SYSENTER_CS, &vmcsGuestSysenterCs) &&
            VmReadChecked(GUEST_SYSENTER_ESP, &vmcsGuestSysenterEsp) &&
            VmReadChecked(GUEST_SYSENTER_EIP, &vmcsGuestSysenterEip) &&
            VmReadChecked(GUEST_DEBUGCTL, &vmcsGuestDebugctl) &&
            VmReadChecked(GUEST_GDTR_BASE, &vmcsGuestGdtBase) &&
            VmReadChecked(GUEST_IDTR_BASE, &vmcsGuestIdtBase) &&
            VmReadChecked(GUEST_GDTR_LIMIT, &vmcsGuestGdtLimit) &&
            VmReadChecked(GUEST_IDTR_LIMIT, &vmcsGuestIdtLimit) &&
            VmReadChecked(GUEST_TR_SELECTOR, &vmcsGuestTr) &&
            VmReadChecked(GUEST_TR_LIMIT, &vmcsGuestTrLimit) &&
            VmReadChecked(GUEST_TR_AR_BYTES, &vmcsGuestTrAr) &&
            VmReadChecked(GUEST_TR_BASE, &vmcsGuestTrBase);
        if (success &&
            (procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) != 0) {
            success = VmReadChecked(
                CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                &vmcsSecondaryCtl);
        }
        if (success &&
            (procCtl & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS) != 0) {
            success = VmReadChecked(
                CONTROL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                &vmcsTertiaryCtl);
        }
        if (success && g_XsavesEnabled) {
            success = VmReadChecked(CONTROL_XSS_EXITING_BITMAP,
                                    &vmcsXssExitingBitmap);
        }
        if (success && g_CetVmcsEnabled) {
            success =
                VmReadChecked(GUEST_S_CET, &vmcsGuestSCet) &&
                VmReadChecked(GUEST_SSP, &vmcsGuestSsp) &&
                VmReadChecked(GUEST_INTR_SSP_TABLE,
                              &vmcsGuestInterruptSspTable);
        }
        readbackComplete = success;
    }
    if (success) {
        // a successful VMREAD only proves that the field encoding was valid
        // compare the values that will drive VM-entry before exposing this
        // VMCS to VMLAUNCH, using the architectural width of each field
        bool valuesMatch = true;
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_CR0, vmcsHostCr0,
                                         hostCr0, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_CR3, vmcsHostCr3,
                                         hostCr3, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_CR4, vmcsHostCr4,
                                         hostCr4, ~0ULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, HOST_RIP, vmcsHostRip,
            reinterpret_cast<u64>(HvVmExitEntryPoint), ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_RSP, vmcsHostRsp,
                                         Vcpu->HostStackTop, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_CS_SELECTOR,
                                         vmcsHostCs,
                                         static_cast<u64>(csSelector & 0xFFF8U),
                                         0xFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_SS_SELECTOR,
                                         vmcsHostSs,
                                         static_cast<u64>(ssSelector & 0xFFF8U),
                                         0xFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_TR_SELECTOR,
                                         vmcsHostTr,
                                         static_cast<u64>(trSelector & 0xFFF8U),
                                         0xFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_FS_BASE,
                                         vmcsHostFsBase, fsBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_GS_BASE,
                                         vmcsHostGsBase, gsBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_EFER, vmcsHostEfer,
                                         hostEfer, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_PAT, vmcsHostPat,
                                         pat, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         HOST_IA32_SYSENTER_CS,
                                         vmcsHostSysenterCs, sysenterCs,
                                         0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         HOST_IA32_SYSENTER_ESP,
                                         vmcsHostSysenterEsp, sysenterEsp,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         HOST_IA32_SYSENTER_EIP,
                                         vmcsHostSysenterEip, sysenterEip,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_TR_BASE,
                                         vmcsHostTrBase, tssBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_GDTR_BASE,
                                         vmcsHostGdtBase, gdtBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, HOST_IDTR_BASE,
                                         vmcsHostIdtBase, vmxHostIdtBase,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS, vmcsPinCtl,
            pinCtl, 0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, CONTROL_EXCEPTION_BITMAP, vmcsExceptionBitmap,
            VMX_EXCEPTION_BITMAP_DOUBLE_FAULT, 0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            vmcsPrimaryCtl, procCtl, 0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, CONTROL_VM_EXIT_CONTROLS,
                                         vmcsExitCtl, exitCtl,
                                         0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, CONTROL_VM_ENTRY_CONTROLS,
                                         vmcsEntryCtl, entryCtl,
                                         0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         CONTROL_MSR_BITMAP_ADDRESS,
                                         vmcsMsrBitmap, Vcpu->MsrBitmapPhys,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         CONTROL_CR0_GUEST_HOST_MASK,
                                         vmcsCr0Mask, 0ULL, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         CONTROL_CR0_READ_SHADOW,
                                         vmcsCr0Shadow, 0ULL, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         CONTROL_CR4_GUEST_HOST_MASK,
                                         vmcsCr4Mask, cr4GuestHostMask, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         CONTROL_CR4_READ_SHADOW,
                                         vmcsCr4Shadow, cr4ReadShadow, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_CR0, vmcsGuestCr0,
                                         guestCr0, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_CR3, vmcsGuestCr3,
                                         guestCr3, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_CR4, vmcsGuestCr4,
                                         guestCr4, ~0ULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, GUEST_RIP, vmcsGuestRip,
            reinterpret_cast<u64>(GuestIp), ~0ULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, GUEST_RSP, vmcsGuestRsp,
            reinterpret_cast<u64>(GuestSp), ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_RFLAGS,
                                         vmcsGuestRflags, guestRflags,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_CS_SELECTOR,
                                         vmcsGuestCs, csSelector, 0xFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_SS_SELECTOR,
                                         vmcsGuestSs, ssSelector, 0xFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_FS_BASE,
                                         vmcsGuestFsBase, fsBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_GS_BASE,
                                         vmcsGuestGsBase, gsBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_EFER, vmcsGuestEfer,
                                         guestEfer, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_PAT, vmcsGuestPat,
                                         guestPat, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         GUEST_SYSENTER_CS,
                                         vmcsGuestSysenterCs, sysenterCs,
                                         0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         GUEST_SYSENTER_ESP,
                                         vmcsGuestSysenterEsp, sysenterEsp,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu,
                                         GUEST_SYSENTER_EIP,
                                         vmcsGuestSysenterEip, sysenterEip,
                                         ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_DEBUGCTL,
                                         vmcsGuestDebugctl,
                                         Vcpu->GuestDebugctl, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_GDTR_BASE,
                                         vmcsGuestGdtBase, gdtBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_IDTR_BASE,
                                         vmcsGuestIdtBase, idtBase, ~0ULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_GDTR_LIMIT,
                                         vmcsGuestGdtLimit, gdtLimit,
                                         0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_IDTR_LIMIT,
                                         vmcsGuestIdtLimit, idtLimit,
                                         0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, GUEST_TR_SELECTOR, vmcsGuestTr, trSelector,
            0xFFFFULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, GUEST_TR_LIMIT, vmcsGuestTrLimit,
            trLimit, 0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(
            mutableVcpu, GUEST_TR_AR_BYTES, vmcsGuestTrAr,
            trAr, 0xFFFFFFFFULL);
        valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_TR_BASE,
                                         vmcsGuestTrBase, tssBase, ~0ULL);
        if ((procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) != 0) {
            valuesMatch &= VmcsValueMatches(
                mutableVcpu,
                CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                vmcsSecondaryCtl, secCtl, 0xFFFFFFFFULL);
        }
        if ((procCtl & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS) != 0) {
            valuesMatch &= VmcsValueMatches(
                mutableVcpu,
                CONTROL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                vmcsTertiaryCtl, tertiaryCtl, ~0ULL);
        }
        if (g_XsavesEnabled) {
            valuesMatch &= VmcsValueMatches(
                mutableVcpu, CONTROL_XSS_EXITING_BITMAP,
                vmcsXssExitingBitmap, 0ULL, ~0ULL);
        }
        if (g_CetVmcsEnabled) {
            u64 vmcsHostSCet = 0;
            u64 vmcsHostSsp = 0;
            u64 vmcsHostInterruptSspTable = 0;
            const bool hostCetReadOk =
                VmReadChecked(HOST_S_CET, &vmcsHostSCet) &&
                VmReadChecked(HOST_SSP, &vmcsHostSsp) &&
                VmReadChecked(HOST_INTR_SSP_TABLE,
                              &vmcsHostInterruptSspTable);
            if (!hostCetReadOk) {
                success = false;
            } else {
                valuesMatch &= VmcsValueMatches(
                    mutableVcpu, HOST_S_CET, vmcsHostSCet, hostSCet, ~0ULL);
                valuesMatch &= VmcsValueMatches(
                    mutableVcpu, HOST_SSP, vmcsHostSsp, hostSsp, ~0ULL);
                valuesMatch &= VmcsValueMatches(
                    mutableVcpu, HOST_INTR_SSP_TABLE,
                    vmcsHostInterruptSspTable, hostInterruptSspTable, ~0ULL);
                valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_S_CET,
                                                 vmcsGuestSCet, guestSCet,
                                                 ~0ULL);
                valuesMatch &= VmcsValueMatches(mutableVcpu, GUEST_SSP,
                                                 vmcsGuestSsp, guestSsp, ~0ULL);
                valuesMatch &= VmcsValueMatches(
                    mutableVcpu, GUEST_INTR_SSP_TABLE,
                    vmcsGuestInterruptSspTable, guestInterruptSspTable,
                    ~0ULL);
            }
        }
        success = success && valuesMatch;
    }
    if (readbackComplete) {
        SetVmcsDiagnosticValidity(mutableVcpu,
                                  HvVmcsValidityVmcsReadback);
    }
    HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup %s: guest_cr3=0x%llX "
                     "guest_rsp=0x%llX guest_rip=0x%llX guest_rflags=0x%llX "
                     "pin=0x%08X exception=0x%08X proc=0x%08X sec=0x%08X "
                     "exit=0x%08X "
                     "entry=0x%08X cet=%u xsaves=%u\n", cpuId,
                     success ? "succeeded" : "FAILED", vmcsGuestCr3,
                     vmcsGuestRsp, vmcsGuestRip, vmcsGuestRflags,
                     pinCtl, static_cast<u32>(vmcsExceptionBitmap), procCtl,
                     secCtl, exitCtl, entryCtl,
                     g_CetVmcsEnabled ? 1U : 0U, g_XsavesEnabled ? 1U : 0U);
    if (success) {
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS host: cr0=0x%llX cr3=0x%llX "
                         "cr4=0x%llX rip=0x%llX rsp=0x%llX cs=0x%llX "
                         "ss=0x%llX tr=0x%llX tr_base=0x%llX "
                         "gdt=0x%llX idt=0x%llX efer=0x%llX pat=0x%llX\n", cpuId,
                         vmcsHostCr0, vmcsHostCr3, vmcsHostCr4, vmcsHostRip,
                         vmcsHostRsp, vmcsHostCs, vmcsHostSs, vmcsHostTr,
                         vmcsHostTrBase, vmcsHostGdtBase, vmcsHostIdtBase,
                         vmcsHostEfer, vmcsHostPat);
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS guest: cr0=0x%llX cr3=0x%llX "
                         "cr4=0x%llX rip=0x%llX rsp=0x%llX rflags=0x%llX "
                         "cs=0x%llX ss=0x%llX tr=0x%llX tr_limit=0x%llX "
                         "tr_ar=0x%llX tr_base=0x%llX gdt=0x%llX idt=0x%llX "
                         "efer=0x%llX pat=0x%llX cet=0x%llX ssp=0x%llX "
                         "ist=0x%llX\n", cpuId, vmcsGuestCr0, vmcsGuestCr3,
                         vmcsGuestCr4, vmcsGuestRip, vmcsGuestRsp,
                         vmcsGuestRflags, vmcsGuestCs, vmcsGuestSs,
                         vmcsGuestTr, vmcsGuestTrLimit, vmcsGuestTrAr,
                         vmcsGuestTrBase, vmcsGuestGdtBase, vmcsGuestIdtBase,
                         vmcsGuestEfer, vmcsGuestPat,
                         vmcsGuestSCet, vmcsGuestSsp,
                         vmcsGuestInterruptSspTable);
    }
    if (!success && ReadVmcsFailureCommitState(mutableVcpu) !=
                         HvVmcsFailureCommitted) {
        PublishVmcsFailure(
            mutableVcpu, HvVmcsFailureReadback,
            static_cast<u64>(InterlockedCompareExchange(
                &mutableVcpu->VmcsSetupPhase, 0, 0)),
            readbackComplete ? 1ULL : 0ULL);
    }
    return success;
}
// ==============================================================================
// Launch Logic
// ==============================================================================


// these symbols form a debugger-readable recorder for the launch rendezvous
// producers only use atomic memory operations because they run at IPI_LEVEL
extern "C" {
// these broadcast helpers are exported by ntoskrnl but are omitted from the
// current WDK headers. HyperDbg uses the same kernel entry points for VMX
// startup and teardown
extern void KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, PVOID Context);
extern void KeSignalCallDpcSynchronize(PVOID SystemArgument2);
extern void KeSignalCallDpcDone(PVOID SystemArgument1);
__declspec(align(64)) volatile LONG g_HvLaunchTelemetrySignature = 0;
volatile LONG g_HvLaunchExpectedProcessors = 0;
volatile LONG g_HvLaunchProbeEntered = 0;
volatile LONG g_HvLaunchProbeCompleted = 0;
volatile LONG g_HvLaunchDispatchEntered = 0;
volatile LONG g_HvLaunchAssemblyEntered = 0;
volatile LONG g_HvLaunchPrepareEntered = 0;
volatile LONG g_HvLaunchPrepareSucceeded = 0;
volatile LONG g_HvLaunchGuestEntered = 0;
volatile LONG g_HvLaunchVmlaunchIssued = 0;
volatile LONG g_HvLaunchVmlaunchReturned = 0;
volatile LONG g_HvLaunchGuestStarted = 0;
volatile LONG g_HvLaunchMarkedLaunched = 0;
volatile LONG g_HvLaunchVmExitAsmReached = 0;
volatile LONG g_HvVmExitDebugHold = 0;
volatile LONG g_HvLaunchFirstVmExitEntered = 0;
volatile LONG g_HvLaunchDispatchReturned = 0;
volatile LONG g_HvLaunchLastProbeProcessor = -1;
volatile LONG g_HvLaunchLastDispatchProcessor = -1;
volatile LONG g_HvLaunchLastPrepareProcessor = -1;
volatile LONG g_HvLaunchLastReturnProcessor = -1;
}

static LONG CurrentProcessorTag() {
    PROCESSOR_NUMBER number = {};
    KeGetCurrentProcessorNumberEx(&number);
    return static_cast<LONG>((static_cast<ULONG>(number.Group) << 16) |
                             static_cast<ULONG>(number.Number));
}

static void RecordLaunchBoundary(volatile LONG* counter,
                                 volatile LONG* lastProcessor) {
    InterlockedExchange(lastProcessor, CurrentProcessorTag());
    InterlockedIncrement(counter);
}

extern "C" ULONG_PTR ProbeIpiRendezvousCallback(ULONG_PTR Context) {
    UNREFERENCED_PARAMETER(Context);
    RecordLaunchBoundary(&g_HvLaunchProbeEntered,
                         &g_HvLaunchLastProbeProcessor);
    return 0;
}

extern "C" ULONG_PTR LaunchIpiDispatchCallback(ULONG_PTR Context) {
    RecordLaunchBoundary(&g_HvLaunchDispatchEntered,
                         &g_HvLaunchLastDispatchProcessor);
    const ULONG_PTR result = EnableHvCallback(Context);
    // EnableHvCallback returns only after the full guest restore thunk has
    // reached this continuation.  Claim GuestActive here, never in the
    // pre-VMLAUNCH wrapper, so a stop rendezvous cannot issue VMXOFF early.
    MarkCurrentVcpuRunning();
    MemoryBarrier();
    RecordLaunchBoundary(&g_HvLaunchDispatchReturned,
                         &g_HvLaunchLastReturnProcessor);
    return result;
}

// hyperdbg enters VMX from the generic DPC itself. Keeping the assembly
// save/restore pair as the direct DPC callee makes the guest return address
// the DPC continuation, without an additional C++ dispatch frame.
static VOID HyperDbgLaunchDpcRoutine(PKDPC Dpc,
                                     PVOID DeferredContext,
                                     PVOID SystemArgument1,
                                     PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);

    (void)EnableHvCallback(0);
    const u32 genericCpu = CurrentProcessorIndex();
    if (g_VcpuData && genericCpu < g_ProcessorCount &&
        InterlockedCompareExchange(&g_VcpuData[genericCpu].State, 0, 0) ==
            VcpuLaunched) {
        MarkCurrentVcpuRunning();
        MemoryBarrier();
    }
    const long genericStage =
        g_VcpuData && genericCpu < g_ProcessorCount
            ? InterlockedCompareExchange(&g_VcpuData[genericCpu].LaunchStage,
                                         0, 0)
            : LaunchStageNone;
    const bool genericGuestActive =
        genericStage == LaunchStageGuestActive;
    // record completion only after the assembly restore has returned to the
    // DPC. The assembly entry counter remains the earliest launch marker
    RecordLaunchBoundary(&g_HvLaunchDispatchReturned,
                         &g_HvLaunchLastReturnProcessor);

    if (!genericGuestActive) {
        HV_VERBOSE_PRINT("[HV] generic DPC returned before GuestActive: "
                         "cpu=%u stage=%ld\n", genericCpu, genericStage);
    }

    // KeGenericCallDpc owns the rendezvous lifetime. Signal only after the
    // VMX transition has returned to this DPC, matching HyperDbg's broadcast
    // callback contract
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

// called by the fixed-frame assembly IPI wrapper. it performs every action
// that may need a compiler-generated stack frame, then returns before
// VMLAUNCH so the assembly restore thunk can own the successful continuation
extern "C" ULONG PrepareHvCallback(ULONG_PTR Context, void* GuestSp, void* GuestIp) {
    RecordLaunchBoundary(&g_HvLaunchPrepareEntered,
                         &g_HvLaunchLastPrepareProcessor);
    UNREFERENCED_PARAMETER(Context);
    if (!g_VcpuData) return 0;
    if (!GuestSp || !GuestIp) return 0;

    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return 0;

    // Debug bring-up: return normally on all non-target processors. Do this
    // before publishing State so StartHypervisor can distinguish "skipped"
    // CPUs from real VMX failures.
    if (!ShouldLaunchOnThisProcessor(id)) {
        return 0;
    }

    VcpuContext* vcpu = &g_VcpuData[id];

    HV_VERBOSE_PRINT("[HV] CPU %u prepare begin: guest_sp=0x%llX guest_ip=0x%llX "
                     "state=%ld\n", id, reinterpret_cast<u64>(GuestSp),
                     reinterpret_cast<u64>(GuestIp),
                     InterlockedCompareExchange(&vcpu->State, 0, 0));

    if (InterlockedCompareExchange(&vcpu->State,
                                   VcpuStarting,
                                   VcpuUninitialized) != VcpuUninitialized) {
        return 0;
    }
    WriteHvTrace(vcpu, id, HvTraceEventDriverEntry);
    WriteHvTrace(vcpu, id, HvTraceEventCpuIpiEnter);
    WriteHvTrace(vcpu, id, HvTraceEventContractBegin);
    InterlockedExchange(&vcpu->LaunchStage, 1);
    InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckEntry);
    InterlockedExchange(&vcpu->TeardownQuiesced, 0);
    InterlockedExchange(&vcpu->TeardownRequest, 0);
    InterlockedExchange(&vcpu->LastEventSnapshotValid, 0);
    vcpu->LaunchCr3Metadata = 0;
    vcpu->LaunchRawGuestCr3 = 0;
    vcpu->LaunchGuestCr3 = 0;
    vcpu->LaunchRawHostCr3 = 0;
    vcpu->LaunchHostCr3 = 0;
    InterlockedExchange(&vcpu->VmcsWriteFailed, 0);
    InterlockedExchange(&vcpu->VmcsWriteState, 0);
    InterlockedExchange(&vcpu->VmcsReadFailed, 0);
    InterlockedExchange(&vcpu->VmcsReadState, 0);
    InterlockedExchange(&vcpu->VmcsFailureCommitState,
                        HvVmcsFailureEmpty);
    InterlockedExchange(&vcpu->VmcsFailureReason,
                        static_cast<LONG>(HvVmcsFailureNone));
    vcpu->VmcsFailureArg0 = 0;
    vcpu->VmcsFailureArg1 = 0;
    InterlockedExchange(&vcpu->LaunchDescriptorRejectMask, 0);
    vcpu->LaunchDescriptorReserved = 0;
    vcpu->LaunchDescriptorSelectorsLow = 0;
    vcpu->LaunchDescriptorSelectorsHigh = 0;
    vcpu->LaunchDescriptorGdtBase = 0;
    vcpu->LaunchDescriptorIdtBase = 0;
    vcpu->LaunchDescriptorTssBase = 0;
    InterlockedExchange(&vcpu->XsetbvExitCount, 0);
    InterlockedExchange(&vcpu->XssWriteExitCount, 0);
    InterlockedExchange(&vcpu->XssWriteRejectCount, 0);
    vcpu->XstateDiagnosticReserved = 0;
    vcpu->LastXsetbvPrevious = 0;
    vcpu->LastXsetbvRequested = 0;
    vcpu->LastXssWritePrevious = 0;
    vcpu->LastXssWriteRequested = 0;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(
                              &vcpu->VmcsDiagnosticValidity),
                          static_cast<LONG64>(HvVmcsValidityNone));
    InterlockedExchange(&vcpu->VmcsValueMismatch, 0);
    InterlockedExchange(&vcpu->VmcsMismatchState, 0);
    InterlockedExchange(&vcpu->VmcsSetupPhase, VmcsSetupPhaseNone);
    InterlockedExchange(&vcpu->FatalSnapshotCommitState,
                        HvFatalSnapshotEmpty);
    InterlockedExchange(&vcpu->FirstExitProbeState, FirstExitProbeIdle);
    InterlockedExchange(&vcpu->FirstExitProbeBaselineVmExits, 0);
    InterlockedExchange(&vcpu->FirstExitProbeBaselineVmResumes, 0);
    InterlockedExchange(&vcpu->FirstExitProbeObservedVmExits, 0);
    InterlockedExchange(&vcpu->FirstExitProbeObservedVmResumes, 0);
    InterlockedExchange(&vcpu->FirstExitProbeReason, 0);
    InterlockedExchange(&vcpu->FirstExitProbeAction, kExitActionNone);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(
                              &vcpu->FirstExitProbeResumeFlags), 0);
    vcpu->FirstVmcsWriteField = 0;
    vcpu->FirstVmcsWriteFlags = 0;
    vcpu->FirstVmcsWriteError = 0;
    vcpu->FirstVmcsReadField = 0;
    vcpu->FirstVmcsReadFlags = 0;
    vcpu->FirstVmcsReadError = 0;
    vcpu->FirstVmcsMismatchField = 0;
    vcpu->FirstVmcsMismatchExpected = 0;
    vcpu->FirstVmcsMismatchActual = 0;
    vcpu->FirstVmcsMismatchMask = 0;
    vcpu->LastVmclearFlags = 0;
    vcpu->LastVmptrldFlags = 0;
    InterlockedExchange(&vcpu->VmcsCurrent, VmcsCurrentStateNone);
    vcpu->PrimaryControlsCapability = 0;
    vcpu->TertiaryControlsAllowed = 0;
    vcpu->LastVmInstructionError = 0;
    vcpu->LastVmResumeFlags = 0;
    vcpu->LastVmInstructionRflags = 0;
    // The bugcheck callback runs at HIGH_LEVEL. Keep the passive-level PT
    // capability sample in the per-CPU record so that callback never has to
    // probe an optional MSR while the machine is already failing.
    vcpu->LastPtCtl = 0;
    vcpu->LastExitReason = 0;
    vcpu->LastExitReasonRaw = 0;
    vcpu->LastExitReasonBasic = 0;
    vcpu->LastExitEntryFailure = 0;
    vcpu->LastExitMsrIndex = 0;
    vcpu->LastExitMsrReserved = 0;
    vcpu->LastExitMsrValue = 0;
    vcpu->LastGuestPendingDbgExceptions = 0;

    volatile bool vmxActive = false;
    volatile bool cr4Prepared = false;
    __try {
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckCpuidAndCr);
        // Capture the executing logical processor's identity before touching
        // CR0, CR4, or VMXON. Alder/Raptor Lake hybrid P/E cores can expose
        // different VMX capability MSRs, so a boot-CPU decision is not enough.
        int localVendor[4] = {};
        __cpuid(localVendor, 0);
        const bool localGenuineIntel =
            static_cast<u32>(localVendor[1]) == 0x756E6547U &&
            static_cast<u32>(localVendor[3]) == 0x49656E69U &&
            static_cast<u32>(localVendor[2]) == 0x6C65746EU;
        if (!localGenuineIntel) {
            HV_VERBOSE_PRINT("[HV] CPU %u rejected: vendor is not GenuineIntel\n",
                             id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u64 localVmxBasic = 0;
        if (!ReadMsrSafe(MSR_IA32_VMX_BASIC, &localVmxBasic)) {
            HV_VERBOSE_PRINT("[HV] CPU %u rejected: VMX_BASIC read failed\n",
                             id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const u32 localProfile = BuildVmxCapabilityProfile(
            localVmxBasic, g_XsavesEnabled != 0, g_CetVmcsEnabled != 0);
        const IntelCpuIdentity identity = QueryIntelCpuIdentity(localProfile);
        if (!IsIntelCpuBranchCompatible(identity, localProfile)) {
            HV_VERBOSE_PRINT("[HV] CPU %u rejected: family=%u model=0x%X "
                             "stepping=%u core_type=0x%X branch=%u "
                             "branch_name=%s profile=0x%X\n", id, identity.Family,
                             identity.Model, identity.Stepping,
                             identity.CoreType,
                             static_cast<u32>(identity.Branch),
                             IntelCpuBranchName(identity.Branch), localProfile);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        vcpu->CpuFamily = identity.Family;
        vcpu->CpuModel = identity.Model;
        vcpu->CpuStepping = identity.Stepping;
        vcpu->CpuCoreType = identity.CoreType;
        vcpu->CpuBranch = static_cast<u32>(identity.Branch);
        vcpu->VmxBasic = localVmxBasic;
        vcpu->VmxProfile = localProfile;
        WriteHvTrace(vcpu, id, HvTraceEventContractBegin,
                     identity.Family, identity.Model, identity.CoreType,
                     static_cast<u64>(identity.Branch));

        // Recheck the immutable feature contract on the processor that will
        // execute VMXON. This catches a heterogeneous package whose E-core
        // capability MSRs do not match the boot processor.
        int localCpuid[4] = {};
        __cpuid(localCpuid, 0);
        const u32 localMaxBasicLeaf = static_cast<u32>(localCpuid[0]);
        __cpuidex(localCpuid, 1, 0);
        if ((localCpuid[2] & (1 << 5)) == 0 ||
            (localCpuid[2] & (1 << 31)) != 0) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (GetDebugctlCapabilityMask() != g_DebugctlMask) {
            HV_VERBOSE_PRINT("[HV] CPU %u DEBUGCTL capability mismatch: "
                             "local=0x%llX expected=0x%llX\n", id,
                             GetDebugctlCapabilityMask(), g_DebugctlMask);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (!EnsureFeatureControlForVmx()) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const u64 localCr4 = __readcr4();
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckXstate);
        const bool localXsaveEnumerated =
            (static_cast<u32>(localCpuid[2]) & CPUID_1_ECX_XSAVE) != 0;
        const bool localOsxsaveEnabled =
            (static_cast<u32>(localCpuid[2]) & CPUID_1_ECX_OSXSAVE) != 0;
        const bool localFxsrEnumerated =
            (static_cast<u32>(localCpuid[3]) & CPUID_1_EDX_FXSR) != 0;
        const bool localUsesXsave = g_XstateMode != XstateSaveFxsave;
        if (localUsesXsave &&
            (localMaxBasicLeaf < 0xD || !localXsaveEnumerated ||
             !localOsxsaveEnabled || (localCr4 & CR4_OSXSAVE) == 0)) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u32 localXsaveAreaSize = FXSAVE_AREA_SIZE;
        u64 localSupportedXcr0 = 0;
        if (localUsesXsave) {
            __cpuidex(localCpuid, 0xD, 0);
            localXsaveAreaSize = static_cast<u32>(localCpuid[1]);
            localSupportedXcr0 = static_cast<u32>(localCpuid[0]) |
                                 (static_cast<u64>(static_cast<u32>(localCpuid[3])) << 32);
        }
        const u64 localCr0 = __readcr0();
        if ((localCr4 & CR4_FRED) != 0) {
            HV_VERBOSE_PRINT("[HV] CPU %u has active unsupported FRED: "
                             "cr4=0x%llX\n", id, localCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (g_XstateMode == XstateSaveFxsave &&
            (!localFxsrEnumerated || (localCr4 & CR4_OSFXSR) == 0 ||
             (localCr4 & CR4_OSXSAVE) != 0 ||
             (localCr4 & CR4_PKE) != 0 ||
             (localCr4 & CR4_FRED) != 0)) {
            HV_VERBOSE_PRINT("[HV] CPU %u lacks the FXSAVE state contract: "
                             "fxsr=%u cr4=0x%llX\n", id,
                             localFxsrEnumerated ? 1U : 0U, localCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localCr0 & ((1ULL << 2) | (1ULL << 3))) != 0) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (!IsFixedCrValueValid(localCr0, MSR_IA32_VMX_CR0_FIXED0,
                                 MSR_IA32_VMX_CR0_FIXED1) ||
            !IsFixedCrValueValid(localCr4 | CR4_VMXE,
                                 MSR_IA32_VMX_CR4_FIXED0,
                                 MSR_IA32_VMX_CR4_FIXED1)) {
            HV_VERBOSE_PRINT("[HV] CPU %u original CR0/CR4 violates VMX fixed "
                             "bits: cr0=0x%llX cr4=0x%llX\n", id, localCr0,
                             localCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const bool localCet = (localCr4 & CR4_CET) != 0;
        if (localCet != (g_CetVmcsEnabled != 0)) {
            HV_VERBOSE_PRINT("[HV] CPU %u local CR4.CET contract mismatch: "
                             "cr4=0x%llX global_cet_vmcs=%u\n", id, localCr4,
                             g_CetVmcsEnabled ? 1U : 0U);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u64 localXcr0 = 0;
        if (localUsesXsave) {
            __try {
                localXcr0 = _xgetbv(0);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        if ((localUsesXsave && ((localXcr0 & ~localSupportedXcr0) != 0 ||
                                 (localXcr0 & 0x3ULL) != 0x3ULL ||
                                 localXcr0 != g_HostXcr0Mask)) ||
            localXsaveAreaSize > VMEXIT_XSAVE_MAX) {
            HV_VERBOSE_PRINT("[HV] CPU %u local XCR0/XSAVE contract mismatch: "
                             "xcr0=0x%llX supported=0x%llX frame=%lu\n",
                             id, localXcr0, localSupportedXcr0,
                             static_cast<ULONG>(localXsaveAreaSize));
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u32 localXsaveFeatures = 0;
        u32 localXsavesSize = 0;
        u64 localXssMask = 0;
        if (localUsesXsave) {
            __cpuidex(localCpuid, 0xD, 1);
            localXsaveFeatures = static_cast<u32>(localCpuid[0]);
            localXsavesSize = static_cast<u32>(localCpuid[1]);
            localXssMask = (static_cast<u32>(localCpuid[2]) |
                            (static_cast<u64>(static_cast<u32>(localCpuid[3])) << 32)) &
                           ~(1ULL << 63);
        }
        u64 localXss = 0;
        const bool localXssRead = localUsesXsave &&
                                  ReadMsrSafe(MSR_IA32_XSS, &localXss);
        if (g_XsavesEnabled && !localXssRead) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localXssRead && (localXss & ~localXssMask) != 0) ||
            (localXssRead && (localXss & ~IA32_XSS_PRESERVABLE_MASK) != 0) ||
            (localXssRead && (localXss & ~g_EnumeratedXssMask) != 0) ||
            (g_XsavesEnabled && localXss != g_HostXssMask) ||
            (!g_XsavesEnabled && localXssRead && localXss != 0) ||
            (localXssRead && (localXss & IA32_XSS_CET_S) != 0)) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localXsaveFeatures & CPUID_D1_XFD) != 0) {
            u64 localXfd = 0;
            u64 localXfdError = 0;
            if (!ReadMsrSafe(MSR_IA32_XFD, &localXfd) ||
                !ReadMsrSafe(MSR_IA32_XFD_ERR, &localXfdError) ||
                localXfd != 0 || localXfdError != 0) {
                HV_VERBOSE_PRINT("[HV] CPU %u active XFD state changed during "
                                 "launch: xfd=0x%llX error=0x%llX\n", id,
                                 localXfd, localXfdError);
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        bool localPtEnumerated = false;
        bool localWaitpkgEnumerated = false;
        bool localCetEnumerated = false;
        bool localCetShadowStackEnumerated = false;
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckCetAndPt);
        if (localMaxBasicLeaf >= 7) {
            __cpuidex(localCpuid, 7, 0);
            const u32 localCpuid7MaxSubleaf = static_cast<u32>(localCpuid[0]);
            localPtEnumerated =
                (static_cast<u32>(localCpuid[1]) & CPUID_7_EBX_INTEL_PT) != 0;
            localWaitpkgEnumerated =
                (static_cast<u32>(localCpuid[2]) & CPUID_7_ECX_WAITPKG) != 0;
            localCetShadowStackEnumerated =
                (static_cast<u32>(localCpuid[2]) & CPUID_7_ECX_CET_SHSTK) != 0;
            localCetEnumerated =
                localCetShadowStackEnumerated ||
                (static_cast<u32>(localCpuid[3]) & CPUID_7_EDX_CET_IBT) != 0;
            if (localCpuid7MaxSubleaf >= 1) {
                __cpuidex(localCpuid, 7, 1);
                const bool localFredEnumerated =
                    (static_cast<u32>(localCpuid[0]) & CPUID_7_1_EAX_FRED) != 0;
                if (localFredEnumerated && (localCr4 & CR4_FRED) != 0) {
                    HV_VERBOSE_PRINT("[HV] CPU %u has active unsupported FRED\n", id);
                    InterlockedExchange(&vcpu->State, VcpuFailed);
                    return 0;
                }
            }
        }
        if (localWaitpkgEnumerated &&
            !VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                              SECONDARY_ENABLE_USER_WAIT_PAUSE)) {
            HV_VERBOSE_PRINT(
                "[HV] CPU %u WAITPKG contract rejected: CPUID.7.0.ECX[5]=1 "
                "but VMX secondary bit 26 cannot be enabled\n",
                id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (localCetEnumerated) {
            // u_cet is per logical processor/thread state, so the boot CPU
            // snapshot cannot prove that this callback is safe. Keep the
            // unsupported active user CET state out of the VMX transition
            u64 localUCet = 0;
            if (!ReadMsrSafe(MSR_IA32_U_CET, &localUCet) ||
                (localUCet & IA32_CET_ENABLE_MASK) != 0) {
                HV_VERBOSE_PRINT("[HV] CPU %u has active unsupported U_CET: "
                                 "value=0x%llX\n", id, localUCet);
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            if (localCetShadowStackEnumerated) {
                u64 localPl3Ssp = 0;
                if (!ReadMsrSafe(MSR_IA32_PL3_SSP, &localPl3Ssp) ||
                    localPl3Ssp != 0) {
                    HV_VERBOSE_PRINT("[HV] CPU %u has active unsupported "
                                     "PL3_SSP: value=0x%llX\n", id,
                                     localPl3Ssp);
                    InterlockedExchange(&vcpu->State, VcpuFailed);
                    return 0;
                }
            }
        }
        if (localPtEnumerated) {
            u64 localPtControl = 0;
            if (!ReadMsrSafe(MSR_IA32_RTIT_CTL, &localPtControl) ||
                (localPtControl & IA32_RTIT_CTL_TRACEEN) != 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            // Capture the value while the CPU is still in passive-level
            // preparation. The high-level crash callback consumes this cache
            // instead of probing an optional PT MSR during bugcheck handling.
            vcpu->LastPtCtl = localPtControl;
        }
        if (g_XsavesEnabled) {
            InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckXsaveLayout);
            u64 localEnumeratedXss = 0;
            u32 localXsaveStateSize = 0;
            const bool localXsaveLayoutValid =
                ComputeXsaveAreaSize(localXcr0, g_XsavesMask,
                                     &localEnumeratedXss,
                                     &localXsaveStateSize);
            if ((localXsaveFeatures & CPUID_D1_XSAVES) == 0 ||
                (g_XsavesMask & ~localXssMask) != 0 ||
                !localXsaveLayoutValid ||
                localEnumeratedXss != localXssMask ||
                localXsavesSize != localXsaveStateSize ||
                localXsaveStateSize != g_XsaveStateSize ||
                localXsaveStateSize > VMEXIT_XSAVE_MAX ||
                !VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                                  SECONDARY_ENABLE_XSAVES)) {
                HV_VERBOSE_PRINT("[HV] CPU %u local XSAVES layout mismatch: "
                "features=0x%X xss=0x%llX fixed=0x%llX "
                "frame=%lu d1_ebx=%lu expected=%lu\n", id,
                localXsaveFeatures, localXssMask, g_XsavesMask,
                static_cast<ULONG>(localXsaveStateSize),
                static_cast<ULONG>(localXsavesSize),
                static_cast<ULONG>(g_XsaveStateSize));
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        } else if (localXsaveAreaSize != g_XsaveStateSize) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckVmxProfile);
        if (g_CetVmcsEnabled) {
            const u32 localExitMsr = ControlMsr(localVmxBasic,
                                                MSR_IA32_VMX_EXIT_CTLS,
                                                MSR_IA32_VMX_TRUE_EXIT_CTLS);
            const u32 localEntryMsr = ControlMsr(localVmxBasic,
                                                 MSR_IA32_VMX_ENTRY_CTLS,
                                                 MSR_IA32_VMX_TRUE_ENTRY_CTLS);
            if (!VmxControlAllows(localExitMsr, VM_EXIT_LOAD_CET_STATE) ||
                !VmxControlAllows(localEntryMsr, VM_ENTRY_LOAD_CET_STATE)) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            u64 localSCet = 0;
            u64 localPl0 = 0;
            u64 localPl1 = 0;
            u64 localPl2 = 0;
            u64 localIst = 0;
            if (!ReadMsrSafe(MSR_IA32_S_CET, &localSCet) ||
                !ReadMsrSafe(MSR_IA32_PL0_SSP, &localPl0) ||
                !ReadMsrSafe(MSR_IA32_PL1_SSP, &localPl1) ||
                !ReadMsrSafe(MSR_IA32_PL2_SSP, &localPl2) ||
                !ReadMsrSafe(MSR_IA32_INTERRUPT_SSP_TABLE, &localIst) ||
                localSCet != 0 || localPl0 != 0 || localPl1 != 0 ||
                localPl2 != 0 || localIst != 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        HV_VERBOSE_PRINT("[HV] CPU %u local contract: CR4=0x%llX XSAVES=%u "
                         "XSS=0x%llX CET_VMCS=%u WAITPKG=%u branch=%s\n", id, localCr4,
                         g_XsavesEnabled ? 1U : 0U,
                         g_XsavesEnabled ? localXss : 0ULL,
                         g_CetVmcsEnabled ? 1U : 0U,
                         localWaitpkgEnumerated ? 1U : 0U,
                         IntelCpuBranchName(identity.Branch));
        const u32 localOptionalProfile =
            vcpu->VmxProfile & kGuestOptionalProfileMask;
        InterlockedAnd(&g_VmxGuestOptionalProfileCandidate,
                       static_cast<LONG>(localOptionalProfile));
        // VMX generation and optional instruction controls are selected per
        // logical processor. Only the global assembly contracts must match:
        // XSAVES changes the save format and CET changes VM-entry/exit fields.
        // P/E cores may otherwise expose different secondary or tertiary
        // controls, which SetupVmcs handles from this local profile.
        constexpr u32 globalProfileMask =
            VmxProfileXsaves | VmxProfileCetVmcs;
        if ((vcpu->VmxProfile & globalProfileMask) !=
            (g_VmxCapabilityProfile & globalProfileMask)) {
            HV_VERBOSE_PRINT("[HV] CPU %u VMX state profile mismatch: "
                             "local=0x%X expected=0x%X required=0x%X\n", id,
                             vcpu->VmxProfile, g_VmxCapabilityProfile,
                             globalProfileMask);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localCr4 & CR4_PKE) != 0 &&
            (localXcr0 & XCR0_PKRU) == 0) {
            HV_VERBOSE_PRINT("[HV] CPU %u has CR4.PKE without PKRU XSTATE: "
                             "cr4=0x%llX xcr0=0x%llX\n", id, localCr4,
                             localXcr0);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        vcpu->RevisionId = static_cast<u32>(vcpu->VmxBasic) &
                           VMX_BASIC_REVISION_MASK;
        const u64 vcpuRegionSize = (vcpu->VmxBasic >> 32) & 0x1FFFULL;
        if (((vcpu->VmxBasic >> 50) & 0xFULL) != 6 ||
            vcpuRegionSize == 0 || vcpuRegionSize > PAGE_SIZE) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((vcpu->VmxBasic & VMX_BASIC_PHYSICAL_ADDRESS_32) &&
            (vcpu->VmxOnPhys > 0xFFFFFFFFULL ||
             vcpu->VmcsPhys > 0xFFFFFFFFULL ||
             vcpu->MsrBitmapPhys > 0xFFFFFFFFULL)) {
            HV_VERBOSE_PRINT("[HV] Processor %u requires 32-bit VMX physical addresses\n", id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((vcpu->HostStackTop & 0x3FULL) != 0 ||
            ((vcpu->HostStackTop - VMEXIT_FRAME_SIZE) & 0x3FULL) != 0) {
            HV_VERBOSE_PRINT("[HV] Processor %u has an unaligned VM-exit XSAVE frame\n", id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckRegions);
        *static_cast<u32*>(vcpu->VmxOnVirt) = vcpu->RevisionId;

        auto* vmcsHeader =
            static_cast<volatile u32*>(vcpu->VmcsVirt);

        vmcsHeader[0] = vcpu->RevisionId;
        vmcsHeader[1] = 0;  // VMX-abort indicator

        if (!ConfigureMsrBitmap(vcpu)) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        // IA32_KERNEL_GS_BASE is not part of VMCS host/guest state.  Reserve
        // one qword immediately below the VMX host stack top so the VM-exit
        // stub can restore the host value before it calls any C++ code.  The
        // guest starts with the same value; subsequent SWAPGS/WRMSR changes
        // are captured in GuestContext and restored before VMRESUME/IRET.
        const u64 hostKernelGs = __readmsr(MSR_IA32_KERNEL_GS_BASE);
        const u64 hostDr7 = GetDr7();
        if (!IsValidGuestDr7(hostDr7)) {
            HV_VERBOSE_PRINT("[HV] CPU %u host DR7 has reserved bits: "
                             "0x%llX\n", id, hostDr7);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u64 hostDebugctl = 0;
        if (!ReadMsrSafe(MSR_IA32_DEBUGCTL, &hostDebugctl)) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (!IsValidDebugctl(hostDebugctl)) {
            HV_VERBOSE_PRINT("[HV] CPU %u host DEBUGCTL has unsupported bits: "
                             "0x%llX\n", id, hostDebugctl);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        // The VM-exit stub allocates 0x1180 bytes below HOST_RSP and reserves
        // the final qword of that frame (offset 0x1178) for this shadow.
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                 (VMEXIT_FRAME_SIZE - VMEXIT_HOST_KGS_OFFSET)) = hostKernelGs;
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                 (VMEXIT_FRAME_SIZE - VMEXIT_HOST_DR7_OFFSET)) = hostDr7;
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                 (VMEXIT_FRAME_SIZE - VMEXIT_HOST_DEBUGCTL_OFFSET)) = hostDebugctl;
        const u64 hostXcr0 = g_XstateMode == XstateSaveFxsave ? 0 : _xgetbv(0);
        u64 hostXss = 0;
        if (g_XsavesEnabled) {
            if (!ReadMsrSafe(MSR_IA32_XSS, &hostXss) ||
                (hostXss & ~g_EnumeratedXssMask) != 0 ||
                (hostXss & ~g_XsavesMask) != 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        // The VM-exit frame reserves these slots immediately below the host
        // KERNEL_GS shadow.  They are read by arch.asm before any C++ code is
        // entered, so initialize them before VMXON/VMLAUNCH.
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                (VMEXIT_FRAME_SIZE - VMEXIT_HOST_XCR0_OFFSET)) = hostXcr0;
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                (VMEXIT_FRAME_SIZE - VMEXIT_HOST_XSS_OFFSET)) = hostXss;
        vcpu->GuestGsBase = __readmsr(MSR_GS_BASE);
        vcpu->GuestKernelGsBase = hostKernelGs;
        vcpu->HostDr7 = hostDr7;
        vcpu->HostDebugctl = hostDebugctl;
        vcpu->GuestDr7 = hostDr7;
        vcpu->GuestDebugctl = hostDebugctl;
        // XCR0 is not saved/restored by VMX transitions.  The VM-exit stub
        // uses the live mask for XSAVE/XRSTOR, so retain the root value and
        // reject guest attempts to switch to a different mask (see the
        // XSETBV exit handler) rather than letting supervisor state bleed
        // into the host C++ continuation.
        vcpu->HostXcr0 = hostXcr0;
        vcpu->GuestXcr0 = hostXcr0;
        vcpu->HostXss = hostXss;
        // This is a late launch inside the already running Windows kernel.
        // Preserve its selector across the handoff; changing IA32_XSS before
        // the first guest instruction would alter the interrupted thread's
        // XSAVES/CET contract.
        vcpu->GuestXss = hostXss;

        vcpu->OriginalCr0 = localCr0;
        vcpu->OriginalCr4 = localCr4;
        vcpu->HostCr3 = g_HostCr3;
        if ((vcpu->HostCr3 & ~static_cast<u64>(PAGE_SIZE - 1)) == 0) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckVmxon);
        __writecr0(AdjustCr0(vcpu->OriginalCr0));
        __writecr4(AdjustCr4(vcpu->OriginalCr4 | CR4_VMXE));
        cr4Prepared = true;

        WriteHvTrace(vcpu, id, HvTraceEventPreVmxon);
        if (ShouldInjectFault(id, HvFaultBeforeVmxon)) {
            WriteHvTrace(vcpu, id, HvTraceEventContractFail,
                         HvFaultBeforeVmxon);
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const u64 vmxonFlags = HvVmxOn(&vcpu->VmxOnPhys);
        WriteHvTrace(vcpu, id, HvTraceEventPostVmxon, vmxonFlags);
        if (!VmxOk(vmxonFlags)) {
            HV_VERBOSE_PRINT("[HV] CPU %u VMXON failed: flags=0x%llX cr0=0x%llX "
                             "cr4=0x%llX vmxon_pa=0x%llX\n", id, vmxonFlags,
                             __readcr0(), __readcr4(), vcpu->VmxOnPhys);
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        vmxActive = true;
        InterlockedExchange(&vcpu->LaunchStage, 2);
        InterlockedExchange(&vcpu->State, VcpuVmxOn);

        if (ShouldInjectFault(id, HvFaultAfterVmxon)) {
            WriteHvTrace(vcpu, id, HvTraceEventContractFail,
                         HvFaultAfterVmxon);
            HvVmxOff();
            vmxActive = false;
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        WriteHvTrace(vcpu, id, HvTraceEventPreVmclear);
        const u64 vmclearFlags = HvVmClear(&vcpu->VmcsPhys);
        WriteHvTrace(vcpu, id, HvTraceEventPostVmclear, vmclearFlags);
        if (ShouldInjectFault(id, HvFaultAfterVmclear)) {
            WriteHvTrace(vcpu, id, HvTraceEventContractFail,
                         HvFaultAfterVmclear);
            PublishVmcsFailure(vcpu, HvVmcsFailureInjected,
                               HvFaultAfterVmclear, vmclearFlags);
            HvVmxOff();
            vmxActive = false;
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        WriteHvTrace(vcpu, id, HvTraceEventPreVmptrld);
        const u64 vmptrldFlags = VmxOk(vmclearFlags)
                                     ? HvVmPtrLd(&vcpu->VmcsPhys)
                                     : vmclearFlags;
        WriteHvTrace(vcpu, id, HvTraceEventPostVmptrld, vmptrldFlags);
        if (VmxOk(vmclearFlags) && VmxOk(vmptrldFlags)) {
            // publish ownership before the fault gate and every later setup
            // step so all VMX-root rollback paths can clear this VMCS
            InterlockedExchange(&vcpu->VmcsCurrent,
                                VmcsCurrentStateActive);
        }
        if (ShouldInjectFault(id, HvFaultAfterVmptrld)) {
            WriteHvTrace(vcpu, id, HvTraceEventContractFail,
                         HvFaultAfterVmptrld);
            PublishVmcsFailure(vcpu, HvVmcsFailureInjected,
                               HvFaultAfterVmptrld, vmptrldFlags);
            if (!HvClearCurrentVmcsAndRecord()) {
                HvFailVmcsClear();
            }
            HvVmxOff();
            vmxActive = false;
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        vcpu->LastVmclearFlags = vmclearFlags;
        vcpu->LastVmptrldFlags = vmptrldFlags;
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckVmcs);
        bool setupVmcsOk = false;
        if (VmxOk(vmclearFlags) && VmxOk(vmptrldFlags)) {
            setupVmcsOk = SetupVmcs(vcpu, GuestSp, GuestIp);
        }
        if (!VmxOk(vmclearFlags) || !VmxOk(vmptrldFlags) ||
            !setupVmcsOk) {
            if (!VmxOk(vmclearFlags)) {
                PublishVmcsFailure(vcpu, HvVmcsFailureVmclear,
                                   vmclearFlags, vcpu->VmcsPhys);
            } else if (!VmxOk(vmptrldFlags)) {
                PublishVmcsFailure(vcpu, HvVmcsFailureVmptrld,
                                   vmptrldFlags, vcpu->VmcsPhys);
            } else if (ReadVmcsFailureCommitState(vcpu) !=
                       HvVmcsFailureCommitted) {
                const long setupPhase = InterlockedCompareExchange(
                    &vcpu->VmcsSetupPhase, 0, 0);
                PublishVmcsFailure(vcpu, HvVmcsFailureReadback,
                                   static_cast<u64>(setupPhase), 0);
            }
            // SetupVmcs can fail after ordinary software validation or a
            // VMWRITE. Preserve an instruction error only when VMPTRLD itself
            // failed with VMfailValid; otherwise the field is not current
            vcpu->LastVmInstructionError = 0;
            ClearVmcsDiagnosticValidity(vcpu,
                                        HvVmcsValidityVmInstructionError);
            const bool vmptrldFailValid =
                VmxOk(vmclearFlags) && !VmxOk(vmptrldFlags) &&
                (vmptrldFlags & (1ULL << 6)) != 0;
            if (vmptrldFailValid) {
                // VM_INSTRUCTION_ERROR is readable only from a valid current
                // VMCS. Prove that the failed VMPTRLD left this processor on
                // the VMCS we own before issuing a diagnostic VMREAD.
                u64 currentPhys = ~0ULL;
                const u64 ptrFlags = HvVmPtrSt(&currentPhys);
                const bool currentVmcsMatches =
                    VmxOk(ptrFlags) && currentPhys != ~0ULL &&
                    currentPhys == vcpu->VmcsPhys;
                WriteHvTrace(vcpu, id, HvTraceEventContractFail,
                             ptrFlags, currentPhys, vcpu->VmcsPhys);
                u64 instructionError = 0;
                if (currentVmcsMatches &&
                    VmReadChecked(VM_INSTRUCTION_ERROR, &instructionError)) {
                    vcpu->LastVmInstructionError = instructionError;
                    SetVmcsDiagnosticValidity(
                        vcpu, HvVmcsValidityVmInstructionError);
                }
            }
            if (!HvClearCurrentVmcsAndRecord()) {
                HvFailVmcsClear();
            }
            HvVmxOff();
            vmxActive = false;
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckXss);
        // VMX does not virtualize IA32_XSS. This callback proceeds directly
        // to VMLAUNCH, so guest XSS is installed only after the live state is
        // captured and never survives a return to Windows in VMX root mode.
        if (g_XsavesEnabled) {
            u64 currentXss = 0;
            if (!ReadMsrSafe(MSR_IA32_XSS, &currentXss) ||
                currentXss != vcpu->HostXss ||
                !WriteMsrSafe(MSR_IA32_XSS, vcpu->GuestXss)) {
                WriteHvTrace(vcpu, id, HvTraceEventContractFail,
                             currentXss, vcpu->HostXss, vcpu->GuestXss);
                HV_VERBOSE_PRINT("[HV] CPU %u IA32_XSS transition rejected: "
                                 "current=0x%llX host=0x%llX guest=0x%llX\n",
                                 id, currentXss, vcpu->HostXss,
                                 vcpu->GuestXss);
                if (!HvClearCurrentVmcsAndRecord()) {
                    HvFailVmcsClear();
                }
                HvVmxOff();
                vmxActive = false;
                (void)WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss);
                __writecr0(vcpu->OriginalCr0);
                __writecr4(vcpu->OriginalCr4);
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }

        // the wrapper publishes Launched immediately before VMLAUNCH, after
        // this preparation has completed. until then this CPU is merely VMXON
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckReady);
        InterlockedExchange(&vcpu->LaunchStage, 4);
        WriteHvTrace(vcpu, id, HvTraceEventContractOk);
        InterlockedIncrement(&g_HvLaunchPrepareSucceeded);
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS ready; entering VMLAUNCH: revision=0x%X "
                         "vmcs_pa=0x%llX host_rsp=0x%llX\n", id, vcpu->RevisionId,
                         vcpu->VmcsPhys, vcpu->HostStackTop);
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckException);
        PublishVmcsFailure(vcpu, HvVmcsFailureException,
                           static_cast<u64>(LaunchCheckException), 0);
        HV_VERBOSE_PRINT("[HV] CPU %u prepare raised an exception: vmx_active=%u "
                         "cr4_prepared=%u\n", id, vmxActive ? 1U : 0U,
                         cr4Prepared ? 1U : 0U);
        if (vmxActive) {
            if (!HvClearCurrentVmcsAndRecord()) {
                HvFailVmcsClear();
            }
            HvVmxOff();
            vmxActive = false;
        }
        if (g_XsavesEnabled) {
            (void)WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss);
        }
        if (cr4Prepared) {
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
        }
        InterlockedExchange(&vcpu->State, VcpuFailed);
        return 0;
    }
}

extern "C" void AbortHvLaunch(u64 Rflags) {
    const u32 id = CurrentProcessorIndex();
    if (!g_VcpuData || id >= g_ProcessorCount) return;
    VcpuContext* vcpu = &g_VcpuData[id];

    // Claim the launch-stage owner before reading or changing VMCS state. A
    // second callback can observe the same VMfail result during a timeout;
    // only the first owner may perform rollback.
    const long oldStage =
        InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0);
    const bool ownsAbortStage =
        (oldStage == LaunchStageReady ||
         oldStage == LaunchStageHandoff ||
         oldStage == LaunchStageVmxOn) &&
        InterlockedCompareExchange(&vcpu->LaunchStage, LaunchStageAbort,
                                    oldStage) == oldStage;
    if (!ownsAbortStage) {
        HV_VERBOSE_PRINT("[HV] CPU %u launch rollback lost stage ownership: "
                         "stage=%ld state=%ld\n", id, oldStage,
                         InterlockedCompareExchange(&vcpu->State, 0, 0));
        return;
    }

    vcpu->LastLaunchFlags = Rflags;
    vcpu->LastVmInstructionRflags = Rflags;
    WriteHvTrace(vcpu, id, HvTraceEventVmlaunchFail, Rflags);

    // HvLaunchGuest returns this private token when its CR4.VMXE guard finds
    // that VMX operation is already inactive. In that case VMREAD/VMXOFF are
    // themselves invalid VMX instructions and must not be attempted.
    const bool markerFailure = Rflags == VMX_LAUNCH_MARKER_FAILURE_MAGIC;
    const bool vmxInstructionFailure = Rflags != VMX_LAUNCH_NOT_VMX_MAGIC;

    // ZF denotes VMfailValid, for which Intel guarantees VM_INSTRUCTION_ERROR
    // is readable. CF denotes VMfailInvalid and has no valid error field.
    u64 errorCode = 0;
    ClearVmcsDiagnosticValidity(vcpu, HvVmcsValidityVmInstructionError);
    if (!markerFailure && vmxInstructionFailure &&
        (Rflags & (1ULL << 6)) != 0) {
        if (VmReadChecked(VM_INSTRUCTION_ERROR, &errorCode)) {
            SetVmcsDiagnosticValidity(vcpu,
                                      HvVmcsValidityVmInstructionError);
        } else {
            InterlockedExchange(&vcpu->VmcsReadFailed, 1);
        }
    }
    vcpu->LastVmInstructionError = errorCode;
    HV_VERBOSE_PRINT("[HV] VMLAUNCH rollback on processor %u flags 0x%llX "
                     "error 0x%llX marker=%u vmx=%u vmfail_valid=%u "
                     "vmcs_read_failed=%ld\n",
                     id, Rflags, errorCode, markerFailure ? 1U : 0U,
                     vmxInstructionFailure ? 1U : 0U,
                     (!markerFailure && vmxInstructionFailure &&
                      (Rflags & (1ULL << 6)) != 0) ? 1U : 0U,
                     InterlockedCompareExchange(&vcpu->VmcsReadFailed, 0, 0));
    WriteHvTrace(vcpu, id, HvTraceEventContractFail, errorCode, Rflags);

    // The NOT_VMX token means the wrapper already observed VMXOFF. It still
    // owns the software stage, but must not issue another VMX instruction.
    if (!vmxInstructionFailure) {
        const long state = InterlockedCompareExchange(&vcpu->State, 0, 0);
        if (state == VcpuVmxOn || state == VcpuLaunched) {
            (void)InterlockedCompareExchange(&vcpu->State, VcpuFailed, state);
        }
        return;
    }

    bool ownsVmx = false;
    // Keep the state live until VMXOFF and all host-register restoration is
    // complete. Publishing Failed earlier lets the cleanup scanner free a
    // VMCS or host stack that the processor still owns.
    const long oldState = InterlockedCompareExchange(&vcpu->State, 0, 0);
    if (oldState == VcpuVmxOn || oldState == VcpuLaunched) {
        ownsVmx = InterlockedCompareExchange(&vcpu->State,
                                              VcpuTearingDown,
                                              oldState) == oldState;
    }
    if (!ownsVmx) {
        HV_VERBOSE_PRINT("[HV] CPU %u launch rollback lost VMX ownership: "
                         "state=%ld stage=%ld\n", id, oldState,
                         InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0));
        return;
    }
    if (ownsVmx) {
        if (!HvClearCurrentVmcsAndRecord()) {
            HvFailVmcsClear();
        }
        HvVmxOff();
    }
    if (ownsVmx && g_XsavesEnabled) {
        (void)WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss);
    }
    if (ownsVmx) {
        __writecr0(vcpu->OriginalCr0);
        __writecr4(vcpu->OriginalCr4);
        InterlockedCompareExchange(&vcpu->State, VcpuFailed,
                                    VcpuTearingDown);
    }
}

// ==============================================================================
// Stop Logic
// ==============================================================================

// this targeted callback must return ULONG_PTR
ULONG_PTR StopHvCallback(ULONG_PTR Context) {
    UNREFERENCED_PARAMETER(Context);

    if (!g_VcpuData) return 0;
    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return 0;
    VcpuContext* vcpu = &g_VcpuData[id];
    const long state = InterlockedCompareExchange(&vcpu->State, 0, 0);
    const long stage = InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0);
    HV_VERBOSE_PRINT("[HV] CPU %u stop callback: state=%ld vmexits=%ld\n", id, state,
                     vcpu->VmExitCount);
    // A VmxOn CPU may still be executing the launch wrapper, and stage 5 is
    // the handoff immediately around VMLAUNCH. Neither state has a proven
    // guest continuation, so do not execute VMXOFF from this callback.
    if (stage == LaunchStageHandoff || state == VcpuVmxOn ||
        state == VcpuStarting) {
        return 0;
    }
    if (state == VcpuStopped || state == VcpuFailed || state == VcpuParked ||
        state == VcpuTearingDown || state == VcpuUninitialized) {
        return 0;
    }
    if (state != VcpuLaunched || stage != LaunchStageGuestActive) return 0;

    // Claim both the lifecycle stage and the state before issuing VMCALL. A
    // concurrent stop owner that loses either CAS must leave the VMX owner
    // untouched; this is the boundary that prevents a second VMXOFF.
    if (InterlockedCompareExchange(&vcpu->LaunchStage,
                                   LaunchStageTeardown,
                                   LaunchStageGuestActive) !=
        LaunchStageGuestActive) {
        return 0;
    }
    if (InterlockedCompareExchange(&vcpu->State, VcpuTearingDown,
                                    VcpuLaunched) != VcpuLaunched) {
        // Roll the stage back only if the same launched owner is still
        // present. A concurrent teardown/abort must keep its terminal stage.
        if (InterlockedCompareExchange(&vcpu->State, 0, 0) == VcpuLaunched) {
            (void)InterlockedCompareExchange(&vcpu->LaunchStage,
                                              LaunchStageGuestActive,
                                              LaunchStageTeardown);
        }
        return 0;
    }
    // Publish the authorization only after both owner CAS operations have
    // succeeded. The assembly marker consumes it exactly once.
    InterlockedExchange(&vcpu->TeardownRequest, 1);
    MemoryBarrier();

    __try {
        // This VMCALL is handled in the guest. The non-returning VMXOFF path
        // resumes at the instruction after VMCALL, so this callback continues
        // with a normal C++ epilogue only after the guest CR4 has VMXE clear.
        HvCall(HYPERVISOR_MAGIC, VMCALL_UNLOAD, 0, 0);
        if ((__readcr4() & CR4_VMXE) != 0) {
            HV_VERBOSE_PRINT("[HV] CPU %u stop returned with CR4.VMXE set; "
                             "retaining VMX state\n", id);
            return 0;
        }
        if (InterlockedCompareExchange(&vcpu->TeardownRequest, 0, 0) != 0) {
            HV_VERBOSE_PRINT("[HV] CPU %u stop returned without teardown "
                             "authorization consumption; retaining state\n",
                             id);
            return 0;
        }
        MemoryBarrier();
        InterlockedExchange(&vcpu->TeardownQuiesced, 1);
        MemoryBarrier();
        if (InterlockedCompareExchange(&vcpu->State, VcpuStopped,
                                       VcpuTearingDown) == VcpuTearingDown) {
            (void)InterlockedCompareExchange(&vcpu->LaunchStage,
                                              LaunchStageStopped,
                                              LaunchStageTeardown);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Do not mark a live CPU as stopped after an exception: the VMX
        // structures may still be referenced by hardware.  StopHypervisor()
        // will refuse to free them and leave a recoverable leak instead.
        HV_VERBOSE_PRINT("[HV] CPU %u stop callback exception; retaining VMX state "
                         "state=%ld stage=%ld vmexits=%ld\n", id,
                         InterlockedCompareExchange(&vcpu->State, 0, 0),
                         InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0),
                         vcpu->VmExitCount);
    }
    return 0;
}

// ==============================================================================
// Native runtime watchdog
// ==============================================================================

static VOID RuntimeWatchdogThread(PVOID Context) {
    const u32 targetCpu =
        static_cast<u32>(reinterpret_cast<ULONG_PTR>(Context));

    GROUP_AFFINITY affinity{};
    GROUP_AFFINITY previousAffinity{};
    bool bound = false;

    PROCESSOR_NUMBER observer{};
    if (NT_SUCCESS(KeGetProcessorNumberFromIndex(kCoordinatorCpuIndex,
                                                  &observer))) {
        affinity.Group = observer.Group;
        affinity.Mask = static_cast<KAFFINITY>(1) << observer.Number;
        KeSetSystemGroupAffinityThread(&affinity, &previousAffinity);
        bound = true;
    }

    LARGE_INTEGER interval{};
    interval.QuadPart = -kRuntimeWatchdogPoll100ns;

    for (;;) {
        if (InterlockedCompareExchange(&g_HvRuntimeWatchdogStop, 0, 0) != 0) {
            break;
        }

        (void)KeDelayExecutionThread(KernelMode, FALSE, &interval);

        if (InterlockedCompareExchange(&g_HvRuntimeWatchdogStop, 0, 0) != 0) {
            break;
        }
        if (!g_VcpuData || targetCpu >= g_ProcessorCount) {
            continue;
        }

        VcpuContext& vcpu = g_VcpuData[targetCpu];
        const LONG tick = InterlockedIncrement(&g_HvRuntimeWatchdogTicks);
        const LONG state = InterlockedCompareExchange(&vcpu.State, 0, 0);
        const LONG stage =
            InterlockedCompareExchange(&vcpu.LaunchStage, 0, 0);
        const LONG vmexits =
            InterlockedCompareExchange(&vcpu.VmExitCount, 0, 0);
        const LONG resumes =
            InterlockedCompareExchange(&vcpu.VmResumeAttempts, 0, 0);
        const LONG reason =
            InterlockedCompareExchange(&vcpu.LastExitReason, 0, 0);
        const LONG action =
            InterlockedCompareExchange(&vcpu.LastExitAction, 0, 0);
        const LONG xssWrites =
            InterlockedCompareExchange(&vcpu.XssWriteExitCount, 0, 0);
        const LONG xssRejects =
            InterlockedCompareExchange(&vcpu.XssWriteRejectCount, 0, 0);
        const LONG xsetbv =
            InterlockedCompareExchange(&vcpu.XsetbvExitCount, 0, 0);
        const LONG fatal =
            InterlockedCompareExchange(&vcpu.FatalSnapshotCommitState, 0, 0);
        const LONG hostFault = InterlockedCompareExchange(
            reinterpret_cast<volatile LONG*>(&g_HvHostFaultRecord.CommitState),
            0, 0);
        const u64 rootNmi = static_cast<u64>(InterlockedCompareExchange64(
            &g_HvRootNmiCount, 0, 0));
        const u64 resumeFlags = static_cast<u64>(InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&vcpu.LastVmResumeFlags),
            0, 0));

        u32 vmxAbort = 0;
        if (vcpu.VmcsVirt) {
            vmxAbort = *reinterpret_cast<volatile u32*>(
                static_cast<u8*>(vcpu.VmcsVirt) + sizeof(u32));
        }

        const bool tripReason =
            reason == static_cast<LONG>(VM_EXIT_REASON_TRIPLE_FAULT);
        const bool trigger =
            vmxAbort != 0 ||
            xssRejects != 0 ||
            resumeFlags != 0 ||
            fatal == HvFatalSnapshotCommitted ||
            hostFault == 2 ||
            tripReason;

        if ((tick % kRuntimeWatchdogPrintEveryTicks) == 0 || trigger) {
            HV_PASSIVE_PRINT(
                "[HV] native watchdog: tick=%ld cpu=%u state=%ld stage=%ld "
                "vmexits=%ld resumes=%ld reason=%ld raw=0x%08X action=%ld "
                "rip=0x%llX rsp=0x%llX cr3=0x%llX "
                "xcr0=0x%llX xss=0x%llX xss_writes=%ld xss_rejects=%ld "
                "xsetbv=%ld root_nmi=%llu resume_flags=0x%llX "
                "vmx_abort=%u fatal=%ld hostfault=%ld\n",
                tick, targetCpu, state, stage, vmexits, resumes, reason,
                vcpu.LastExitReasonRaw, action,
                vcpu.LastGuestRip, vcpu.LastGuestRsp, vcpu.LastGuestCr3,
                vcpu.LastGuestXcr0, vcpu.LastGuestXss,
                xssWrites, xssRejects, xsetbv, rootNmi, resumeFlags,
                vmxAbort, fatal, hostFault);
        }

        if (trigger &&
            InterlockedCompareExchange(&g_HvRuntimeWatchdogBreakFired,
                                       1, 0) == 0) {
            HV_PASSIVE_PRINT(
                "[HV] native watchdog BREAK: cpu=%u vmx_abort=%u "
                "reason=%ld raw=0x%08X xss_rejects=%ld "
                "resume_flags=0x%llX fatal=%ld hostfault=%ld\n",
                targetCpu, vmxAbort, reason, vcpu.LastExitReasonRaw,
                xssRejects, resumeFlags, fatal, hostFault);
            DbgBreakPoint();
        }
    }

    if (bound) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS StartRuntimeWatchdog(u32 targetCpu) {
    if (!g_HvDriverObject || g_HvRuntimeWatchdogThread != nullptr ||
        targetCpu >= g_ProcessorCount) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InterlockedExchange(&g_HvRuntimeWatchdogStop, 0);
    InterlockedExchange(&g_HvRuntimeWatchdogTicks, 0);
    InterlockedExchange(&g_HvRuntimeWatchdogBreakFired, 0);

    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);

    HANDLE threadHandle = nullptr;
    const NTSTATUS status = IoCreateSystemThread(
        g_HvDriverObject, &threadHandle, SYNCHRONIZE, &attributes,
        nullptr, nullptr, RuntimeWatchdogThread,
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(targetCpu)));
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_HvRuntimeWatchdogStop, 1);
        return status;
    }

    g_HvRuntimeWatchdogThread = threadHandle;
    return STATUS_SUCCESS;
}

static void StopRuntimeWatchdog() {
    HANDLE threadHandle = g_HvRuntimeWatchdogThread;
    if (!threadHandle) return;

    InterlockedExchange(&g_HvRuntimeWatchdogStop, 1);
    (void)ZwWaitForSingleObject(threadHandle, FALSE, nullptr);
    ZwClose(threadHandle);
    g_HvRuntimeWatchdogThread = nullptr;
}

// ==============================================================================
// Public API
// ===============================================================================

static void StopHypervisorInternal(bool startRollback);
static void PinImageForParkedCpu();

static bool IsTargetWorkTerminal(LONG state) {
    return state == TargetWorkSucceeded || state == TargetWorkFailed ||
           state == TargetWorkCancelled;
}

static bool IsVcpuStopTerminal(long state) {
    return state == VcpuStopped || state == VcpuFailed ||
           state == VcpuUninitialized;
}

static VOID TargetCpuWorker(PVOID Context) {
    auto* work = static_cast<TargetCpuWork*>(Context);
    if (!work) {
        return;
    }

    if (!g_VcpuData || work->ProcessorIndex >= g_ProcessorCount) {
        work->Result = STATUS_INVALID_DEVICE_STATE;
        work->ReturnTime = KeQueryInterruptTime();
        MemoryBarrier();
        InterlockedExchange(&work->State, TargetWorkFailed);
        return;
    }

    if (InterlockedCompareExchange(&work->State,
                                   TargetWorkEntered,
                                   TargetWorkQueued) != TargetWorkQueued) {
        const LONG state = InterlockedCompareExchange(&work->State, 0, 0);
        if (state != TargetWorkCancelled && !IsTargetWorkTerminal(state)) {
            work->Result = STATUS_CANCELLED;
            work->ReturnTime = KeQueryInterruptTime();
            MemoryBarrier();
            InterlockedExchange(&work->State, TargetWorkFailed);
        }
        return;
    }

    work->EnterTime = KeQueryInterruptTime();
    GROUP_AFFINITY affinity{};
    GROUP_AFFINITY previousAffinity{};
    affinity.Group = work->Target.Group;
    affinity.Mask = static_cast<KAFFINITY>(1) << work->Target.Number;
    KeSetSystemGroupAffinityThread(&affinity, &previousAffinity);

    PROCESSOR_NUMBER current{};
    KeGetCurrentProcessorNumberEx(&current);
    work->ObservedProcessorTag =
        static_cast<LONG>((static_cast<ULONG>(current.Group) << 16) |
                          static_cast<ULONG>(current.Number));

    NTSTATUS result = STATUS_INVALID_DEVICE_STATE;
    if (current.Group == work->Target.Group &&
        current.Number == work->Target.Number &&
        InterlockedCompareExchange(&work->State,
                                   TargetWorkExecuting,
                                   TargetWorkEntered) == TargetWorkEntered) {
        InterlockedExchange(&g_HvTargetActiveProcessor,
                            static_cast<LONG>(work->ProcessorIndex));
        const LONG operation = work->Operation;
        if (operation == TargetOperationProbe) {
            ProbeIpiRendezvousCallback(0);
            result = STATUS_SUCCESS;
        } else if (operation == TargetOperationLaunch) {
            // a launch must never use a temporary worker stack. the startup
            // path routes this operation through TargetLaunchDpcRoutine.
            result = STATUS_NOT_SUPPORTED;
        } else if (operation == TargetOperationRuntimeCanary) {
            VcpuContext* vcpu = &g_VcpuData[work->ProcessorIndex];
            const long vcpuState =
                InterlockedCompareExchange(&vcpu->State, 0, 0);
            if (vcpuState != VcpuLaunched) {
                result = STATUS_INVALID_DEVICE_STATE;
            } else {
                const long baselineExits =
                    InterlockedCompareExchange(&vcpu->VmExitCount, 0, 0);
                const long baselineResumes =
                    InterlockedCompareExchange(&vcpu->VmResumeAttempts, 0, 0);
                InterlockedExchange(&work->CanaryBaselineVmExits,
                                    baselineExits);
                InterlockedExchange(&work->CanaryBaselineVmResumes,
                                    baselineResumes);
                InterlockedExchange(&work->CanaryIrql,
                                    static_cast<LONG>(KeGetCurrentIrql()));
                work->CanaryCr3 = __readcr3();
                work->CanaryCr4 = __readcr4();

                int regs[4] = {};
                __cpuidex(regs, 0, 0);

                work->CanaryCpuidEax = static_cast<u32>(regs[0]);
                work->CanaryCpuidEbx = static_cast<u32>(regs[1]);
                work->CanaryCpuidEcx = static_cast<u32>(regs[2]);
                work->CanaryCpuidEdx = static_cast<u32>(regs[3]);

                const long observedExits =
                    InterlockedCompareExchange(&vcpu->VmExitCount, 0, 0);
                const long observedResumes =
                    InterlockedCompareExchange(&vcpu->VmResumeAttempts, 0, 0);
                const long lastReason =
                    InterlockedCompareExchange(&vcpu->LastExitReason, 0, 0);
                InterlockedExchange(&work->CanaryObservedVmExits,
                                    observedExits);
                InterlockedExchange(&work->CanaryObservedVmResumes,
                                    observedResumes);
                InterlockedExchange(&work->CanaryLastExitReason, lastReason);

                const bool intelVendor =
                    work->CanaryCpuidEbx == 0x756E6547U &&
                    work->CanaryCpuidEdx == 0x49656E69U &&
                    work->CanaryCpuidEcx == 0x6C65746EU;
                const bool exitAdvanced = observedExits >= baselineExits + 1;
                const bool resumeAdvanced =
                    observedResumes >= baselineResumes + 1;
                const bool cpuidExit =
                    lastReason == static_cast<long>(VM_EXIT_REASON_CPUID);
                const bool resumeClean =
                    static_cast<u64>(InterlockedCompareExchange64(
                        reinterpret_cast<volatile LONG64*>(
                            &vcpu->LastVmResumeFlags), 0, 0)) == 0;
                const bool stillLaunched =
                    InterlockedCompareExchange(&vcpu->State, 0, 0) ==
                    VcpuLaunched;

                WriteHvTrace(vcpu, work->ProcessorIndex,
                             HvTraceEventPostDpcCanary,
                             static_cast<u64>(baselineExits),
                             static_cast<u64>(observedExits),
                             static_cast<u64>(baselineResumes),
                             static_cast<u64>(observedResumes));

                result = intelVendor && exitAdvanced && resumeAdvanced &&
                                 cpuidExit && resumeClean && stillLaunched
                             ? STATUS_SUCCESS
                             : STATUS_UNSUCCESSFUL;
            }
        } else if (operation == TargetOperationStop) {
            StopHvCallback(static_cast<ULONG_PTR>(work->Generation));
            const long stoppedState = InterlockedCompareExchange(
                &g_VcpuData[work->ProcessorIndex].State, 0, 0);
            result = IsVcpuStopTerminal(stoppedState)
                         ? STATUS_SUCCESS
                         : STATUS_UNSUCCESSFUL;
        }
        InterlockedExchange(&g_HvTargetActiveProcessor, -1);
    } else if (InterlockedCompareExchange(&work->State, 0, 0) ==
               TargetWorkCancelled) {
        result = STATUS_CANCELLED;
    }

    KeRevertToUserGroupAffinityThread(&previousAffinity);
    work->Result = result;
    work->ReturnTime = KeQueryInterruptTime();
    MemoryBarrier();
    if (InterlockedCompareExchange(&work->State, 0, 0) !=
        TargetWorkCancelled) {
        InterlockedExchange(&work->State,
                            NT_SUCCESS(result) ? TargetWorkSucceeded
                                               : TargetWorkFailed);
    }
}

static VOID TargetLaunchDpcRoutine(PKDPC Dpc,
                                   PVOID DeferredContext,
                                   PVOID SystemArgument1,
                                   PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    auto* work = static_cast<TargetLaunchDpcWork*>(DeferredContext);
    if (!work) return;

    work->EnterTime = KeQueryInterruptTime();
    work->ObservedIrql = static_cast<LONG>(KeGetCurrentIrql());
    PROCESSOR_NUMBER current{};
    KeGetCurrentProcessorNumberEx(&current);
    work->ObservedProcessorTag =
        static_cast<LONG>((static_cast<ULONG>(current.Group) << 16) |
                          static_cast<ULONG>(current.Number));

    NTSTATUS result = STATUS_INVALID_DEVICE_STATE;
    const LONG priorState = InterlockedCompareExchange(
        &work->State, TargetWorkExecuting, TargetWorkQueued);
    if (priorState == TargetWorkQueued &&
        current.Group == work->Target.Group &&
        current.Number == work->Target.Number) {
        InterlockedExchange(&g_HvTargetActiveProcessor,
                            static_cast<LONG>(work->ProcessorIndex));
        // keep the assembly entry as the direct DPC callee like HyperDbg's
        // DpcRoutineInitializeGuest, while this target DPC tracks completion
        // without the generic broadcast barrier
        // publish the DPC boundary before entering assembly so a fatal stop
        // can distinguish a callback that never reached PrepareHvCallback
        if (g_VcpuData && work->ProcessorIndex < g_ProcessorCount) {
            InterlockedExchange(
                &g_VcpuData[work->ProcessorIndex].LaunchCheckStage,
                LaunchCheckEntry);
        }
        RecordLaunchBoundary(&g_HvLaunchDispatchEntered,
                             &g_HvLaunchLastDispatchProcessor);
        (void)EnableHvCallback(0);
        const long launchState =
            g_VcpuData && work->ProcessorIndex < g_ProcessorCount
                ? InterlockedCompareExchange(
                      &g_VcpuData[work->ProcessorIndex].State, 0, 0)
                : VcpuFailed;
        // state == VcpuLaunched is the precondition for the guest-active
        // publication; the marker itself validates the handoff stage atomically
        if (launchState == VcpuLaunched) {
            MarkCurrentVcpuRunning();
            MemoryBarrier();
        }
        const long launchStage =
            g_VcpuData && work->ProcessorIndex < g_ProcessorCount
                ? InterlockedCompareExchange(
                      &g_VcpuData[work->ProcessorIndex].LaunchStage, 0, 0)
                : LaunchStageNone;
        const bool guestActive = launchState == VcpuLaunched &&
                                 launchStage == LaunchStageGuestActive;
        bool firstExitProbePassed = guestActive;
        if constexpr (kEnableLaunchFirstExitProbe) {
            firstExitProbePassed =
                guestActive && g_VcpuData &&
                RunFirstExitProbe(&g_VcpuData[work->ProcessorIndex],
                                  work->ProcessorIndex);
        }
        if (firstExitProbePassed) {
            // this is the last recoverable boundary before the DPC reports
            // success to the coordinator, matching the generic DPC telemetry
            RecordLaunchBoundary(&g_HvLaunchDispatchReturned,
                                 &g_HvLaunchLastReturnProcessor);
        }
        result = firstExitProbePassed
                     ? STATUS_SUCCESS
                     : STATUS_UNSUCCESSFUL;
        InterlockedExchange(&g_HvTargetActiveProcessor, -1);
    } else if (priorState == TargetWorkCancelled) {
        result = STATUS_CANCELLED;
    }

    work->Result = result;
    work->ReturnTime = KeQueryInterruptTime();
    MemoryBarrier();
    if (InterlockedCompareExchange(&work->State, 0, 0) !=
        TargetWorkCancelled) {
        InterlockedExchange(&work->State,
                            NT_SUCCESS(result) ? TargetWorkSucceeded
                                               : TargetWorkFailed);
    }
    InterlockedExchange(&work->DpcCompleted, 1);
    KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
}

static LARGE_INTEGER RemainingTargetTimeout(u64 deadline);

static NTSTATUS QueueTargetLaunchDpc(u32 processorIndex) {
    if (!g_HvTargetLaunchDpcWork || processorIndex >= g_ProcessorCount) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    TargetLaunchDpcWork* work = &g_HvTargetLaunchDpcWork[processorIndex];
    if (InterlockedCompareExchange(&work->DpcQueued, 1, 0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    NTSTATUS status = KeGetProcessorNumberFromIndex(processorIndex,
                                                    &work->Target);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&work->DpcQueued, 0);
        return status;
    }

    work->ProcessorIndex = processorIndex;
    work->Generation = InterlockedIncrement(&g_HvTargetWorkGeneration);
    InterlockedExchange(&work->State, TargetWorkQueued);
    InterlockedExchange(&work->TimedOut, 0);
    InterlockedExchange(&work->DpcCompleted, 0);
    InterlockedExchange(&work->ObservedProcessorTag, -1);
    InterlockedExchange(&work->ObservedIrql, -1);
    work->Result = STATUS_PENDING;
    work->QueueTime = KeQueryInterruptTime();
    work->EnterTime = 0;
    work->ReturnTime = 0;
    KeInitializeEvent(&work->Done, SynchronizationEvent, FALSE);
    KeInitializeDpc(&work->Dpc, TargetLaunchDpcRoutine, work);
    status = KeSetTargetProcessorDpcEx(&work->Dpc, &work->Target);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&work->DpcQueued, 0);
        InterlockedExchange(&work->State, TargetWorkFailed);
        InterlockedExchange(&work->DpcCompleted, 1);
        work->Result = status;
        KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
        return status;
    }
    if (!KeInsertQueueDpc(&work->Dpc, nullptr, nullptr)) {
        InterlockedExchange(&work->DpcQueued, 0);
        InterlockedExchange(&work->State, TargetWorkFailed);
        InterlockedExchange(&work->DpcCompleted, 1);
        work->Result = STATUS_UNSUCCESSFUL;
        KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WaitTargetLaunchDpc(u32 processorIndex,
                                    u64 deadline,
                                    bool* unresolved) {
    if (!g_HvTargetLaunchDpcWork || processorIndex >= g_ProcessorCount ||
        !unresolved) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetLaunchDpcWork* work = &g_HvTargetLaunchDpcWork[processorIndex];
    if (InterlockedCompareExchange(&work->DpcQueued, 0, 0) == 0) {
        return work->Result;
    }

    LARGE_INTEGER timeout = RemainingTargetTimeout(deadline);
    NTSTATUS waitStatus = KeWaitForSingleObject(&work->Done,
                                                Executive,
                                                KernelMode,
                                                FALSE,
                                                &timeout);
    if (waitStatus == STATUS_SUCCESS) {
        // The completion event is set just before the DPC returns. Drain the
        // active callback before allowing its bookkeeping to be reused.
        (void)KeRemoveQueueDpcEx(&work->Dpc, TRUE);
        InterlockedExchange(&work->DpcQueued, 0);
        return work->Result;
    }

    if (waitStatus == STATUS_TIMEOUT && KeRemoveQueueDpc(&work->Dpc)) {
        InterlockedExchange(&work->State, TargetWorkCancelled);
        InterlockedExchange(&work->DpcCompleted, 1);
        InterlockedExchange(&work->DpcQueued, 0);
        work->Result = STATUS_IO_TIMEOUT;
        KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
        return STATUS_IO_TIMEOUT;
    }

    InterlockedExchange(&work->TimedOut, 1);
    *unresolved = true;
    return waitStatus == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : waitStatus;
}

static NTSTATUS QueueTargetOperation(u32 processorIndex,
                                     TargetOperation operation) {
    if (!g_HvTargetCpuWork || !g_HvDriverObject ||
        processorIndex >= g_ProcessorCount) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    TargetCpuWork* work = &g_HvTargetCpuWork[processorIndex];
    if (work->ThreadHandle != nullptr) return STATUS_DEVICE_BUSY;

    RtlZeroMemory(work, sizeof(*work));
    NTSTATUS status = KeGetProcessorNumberFromIndex(processorIndex,
                                                     &work->Target);
    if (!NT_SUCCESS(status)) return status;

    work->ProcessorIndex = processorIndex;
    work->Generation = InterlockedIncrement(&g_HvTargetWorkGeneration);
    work->Operation = operation;
    work->Result = STATUS_PENDING;
    work->QueueTime = KeQueryInterruptTime();
    InterlockedExchange(&work->State, TargetWorkQueued);

    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE threadHandle = nullptr;
    status = IoCreateSystemThread(g_HvDriverObject,
                                  &threadHandle,
                                  SYNCHRONIZE,
                                  &attributes,
                                  nullptr,
                                  nullptr,
                                  TargetCpuWorker,
                                  work);
    if (!NT_SUCCESS(status)) {
        work->Result = status;
        InterlockedExchange(&work->State, TargetWorkFailed);
        return status;
    }

    work->ThreadHandle = threadHandle;
    MemoryBarrier();
    return STATUS_SUCCESS;
}

static LARGE_INTEGER RemainingTargetTimeout(u64 deadline) {
    LARGE_INTEGER timeout{};
    const u64 now = KeQueryInterruptTime();
    if (now < deadline) {
        timeout.QuadPart = -static_cast<LONGLONG>(deadline - now);
    }
    return timeout;
}

static NTSTATUS CloseCompletedTargetWork(TargetCpuWork* work) {
    const NTSTATUS result = work->Result;
    HANDLE threadHandle = work->ThreadHandle;
    work->ThreadHandle = nullptr;
    if (threadHandle) ZwClose(threadHandle);
    return result;
}

static NTSTATUS WaitTargetOperation(u32 processorIndex,
                                    u64 deadline,
                                    bool* unresolved) {
    if (!g_HvTargetCpuWork || processorIndex >= g_ProcessorCount ||
        !unresolved) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetCpuWork* work = &g_HvTargetCpuWork[processorIndex];
    HANDLE threadHandle = work->ThreadHandle;
    if (!threadHandle) return work->Result;

    LARGE_INTEGER timeout = RemainingTargetTimeout(deadline);
    NTSTATUS waitStatus = ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
    if (waitStatus == STATUS_SUCCESS) {
        return CloseCompletedTargetWork(work);
    }

    if (waitStatus == STATUS_TIMEOUT) {
        bool cancelled =
            InterlockedCompareExchange(&work->State,
                                       TargetWorkCancelled,
                                       TargetWorkQueued) == TargetWorkQueued;
        if (!cancelled) {
            cancelled =
                InterlockedCompareExchange(&work->State,
                                           TargetWorkCancelled,
                                           TargetWorkEntered) == TargetWorkEntered;
        }

        const LONG state = InterlockedCompareExchange(&work->State, 0, 0);
        if (cancelled || IsTargetWorkTerminal(state)) {
            LARGE_INTEGER grace{};
            grace.QuadPart = -kTargetCancelGrace100ns;
            if (ZwWaitForSingleObject(threadHandle, FALSE, &grace) ==
                STATUS_SUCCESS) {
                (void)CloseCompletedTargetWork(work);
                return STATUS_IO_TIMEOUT;
            }
        }
    }

    InterlockedExchange(&work->TimedOut, 1);
    *unresolved = true;
    return waitStatus == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : waitStatus;
}


static NTSTATUS RunRuntimeCanary(u32 processorIndex,
                                 const char* phase,
                                 bool* unresolved) {
    if (!g_HvTargetCpuWork || processorIndex >= g_ProcessorCount ||
        !unresolved) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status =
        QueueTargetOperation(processorIndex, TargetOperationRuntimeCanary);
    if (NT_SUCCESS(status)) {
        const u64 deadline =
            KeQueryInterruptTime() + kTargetOperationTimeout100ns;
        status = WaitTargetOperation(processorIndex, deadline, unresolved);
    }

    TargetCpuWork* work = &g_HvTargetCpuWork[processorIndex];
    HV_PASSIVE_PRINT(
        "[HV] %s canary: cpu=%u status=0x%08X worker_state=%ld irql=%ld "
        "vmexits=%ld->%ld resumes=%ld->%ld reason=%ld "
        "cpuid=%08X-%08X-%08X-%08X cr3=0x%llX cr4=0x%llX\n",
        phase ? phase : "runtime",
        processorIndex,
        static_cast<ULONG>(status),
        InterlockedCompareExchange(&work->State, 0, 0),
        InterlockedCompareExchange(&work->CanaryIrql, 0, 0),
        InterlockedCompareExchange(&work->CanaryBaselineVmExits, 0, 0),
        InterlockedCompareExchange(&work->CanaryObservedVmExits, 0, 0),
        InterlockedCompareExchange(&work->CanaryBaselineVmResumes, 0, 0),
        InterlockedCompareExchange(&work->CanaryObservedVmResumes, 0, 0),
        InterlockedCompareExchange(&work->CanaryLastExitReason, 0, 0),
        work->CanaryCpuidEax,
        work->CanaryCpuidEbx,
        work->CanaryCpuidEcx,
        work->CanaryCpuidEdx,
        work->CanaryCr3,
        work->CanaryCr4);

    return status;
}

static bool BindCoordinatorToProcessor(u32 processorIndex,
                                       GROUP_AFFINITY* previousAffinity) {
    if (!previousAffinity || processorIndex >= g_ProcessorCount) return false;
    PROCESSOR_NUMBER target{};
    if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processorIndex, &target))) {
        return false;
    }

    GROUP_AFFINITY affinity{};
    affinity.Group = target.Group;
    affinity.Mask = static_cast<KAFFINITY>(1) << target.Number;
    KeSetSystemGroupAffinityThread(&affinity, previousAffinity);

    PROCESSOR_NUMBER current{};
    KeGetCurrentProcessorNumberEx(&current);
    if (current.Group == target.Group && current.Number == target.Number) {
        return true;
    }

    KeRevertToUserGroupAffinityThread(previousAffinity);
    return false;
}

// Keep the affinity token paired with the exact successful bind. Reverting
// once, at the end of the startup transaction, prevents the caller from
// migrating onto a VMX guest CPU while diagnostics and profile publication are
// still using the coordinator's stack.
static void ReleaseCoordinatorAffinity(GROUP_AFFINITY* previousAffinity,
                                        bool* bound) {
    if (!previousAffinity || !bound || !*bound) return;
    KeRevertToUserGroupAffinityThread(previousAffinity);
    *bound = false;
}

static bool HasUnresolvedTargetWork() {
    if (!g_HvTargetCpuWork && !g_HvTargetLaunchDpcWork) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        // A timeout is unresolved while either a worker handle or a launch
        // DPC can still execute against the retained VMX storage.
        if (g_HvTargetCpuWork &&
            g_HvTargetCpuWork[i].ThreadHandle != nullptr) {
            return true;
        }
        if (g_HvTargetLaunchDpcWork &&
            InterlockedCompareExchange(&g_HvTargetLaunchDpcWork[i].DpcQueued,
                                       0, 0) != 0) {
            return true;
        }
    }
    return false;
}

static NTSTATUS QuarantineUnresolvedTargetWork() {
    PinImageForParkedCpu();
    InterlockedExchange(&g_HvLifecycle, kHvLifecycleQuarantined);
    return STATUS_SUCCESS;
}

static bool LaunchResultNeedsDetail(u32 processorIndex,
                                    const VcpuContext& vcpu) {
    if (!ShouldReportLaunchResult(processorIndex)) return false;
    const long state = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.State), 0, 0);
    const long action = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.LastExitAction), 0, 0);
    const long vmcsWriteFailed = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsWriteFailed), 0, 0);
    const long vmcsReadFailed = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsReadFailed), 0, 0);
    const long vmcsValueMismatch = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsValueMismatch), 0, 0);
    const u64 diagnosticValidity = ReadVmcsDiagnosticValidity(&vcpu);
    bool needsDetail = state != VcpuLaunched ||
                       action == kExitActionHalt ||
           vcpu.LastExitEntryFailure != 0 ||
           vcpu.LastVmInstructionError != 0 ||
           (diagnosticValidity & HvVmcsValidityVmInstructionError) != 0 ||
           vcpu.LastVmResumeFlags != 0 ||
           vmcsWriteFailed != 0 || vmcsReadFailed != 0 ||
           vmcsValueMismatch != 0 ||
           vcpu.LastExitReasonBasic == VM_EXIT_REASON_TRIPLE_FAULT ||
           vcpu.LastExitReasonBasic == VM_EXIT_REASON_INVALID_GUEST_STATE;
    if constexpr (kEnableLaunchFirstExitProbe) {
        const long firstExitProbeState = ReadFirstExitProbeState(&vcpu);
        needsDetail = needsDetail ||
                      (!kUseHyperDbgGenericLaunch &&
                       firstExitProbeState != FirstExitProbeReturned);
    }
    return needsDetail;
}

static void PrintLaunchResult(u32 processorIndex, const VcpuContext& vcpu) {
    if (!ShouldReportLaunchResult(processorIndex)) return;
    const long state = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.State), 0, 0);
    const long stage = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.LaunchStage), 0, 0);
    const long checkStage = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.LaunchCheckStage), 0, 0);
    const long vmExitCount = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmExitCount), 0, 0);
    const long firstExitProbeState = ReadFirstExitProbeState(&vcpu);
    const long firstExitProbeExits = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.FirstExitProbeObservedVmExits), 0, 0);
    const long firstExitProbeResumes = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.FirstExitProbeObservedVmResumes), 0, 0);
    const long action = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.LastExitAction), 0, 0);
    const long vmcsWriteFailed = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsWriteFailed), 0, 0);
    const long vmcsReadFailed = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsReadFailed), 0, 0);
    const long vmcsValueMismatch = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsValueMismatch), 0, 0);
    const u64 diagnosticValidity = ReadVmcsDiagnosticValidity(&vcpu);
    const u64 launchRawGuestCr3 =
        ReadLaunchCr3Field(&vcpu.LaunchRawGuestCr3);
    const u64 launchGuestCr3 = ReadLaunchCr3Field(&vcpu.LaunchGuestCr3);
    const u64 launchRawHostCr3 =
        ReadLaunchCr3Field(&vcpu.LaunchRawHostCr3);
    const u64 launchHostCr3 = ReadLaunchCr3Field(&vcpu.LaunchHostCr3);
    const u64 launchCr3Metadata =
        ReadLaunchCr3Field(&vcpu.LaunchCr3Metadata);
    if (!LaunchResultNeedsDetail(processorIndex, vcpu)) {
        // keep the normal path below the debugger transport's burst size
        HV_PASSIVE_PRINT(
            "[HV] CPU %u launch result: state=%ld stage=%ld check=%ld "
            "vmexits=%ld probe=%ld probe_exits=%ld probe_resumes=%ld "
            "action=%ld resumes=%ld reason=0x%08X "
            "msr=0x%08X cr3_guest=0x%llX cr3_host=0x%llX "
            "cr3_meta=0x%llX\n",
            processorIndex, state, stage, checkStage, vmExitCount,
            firstExitProbeState, firstExitProbeExits, firstExitProbeResumes,
            action,
            vcpu.VmResumeAttempts, vcpu.LastExitReasonBasic,
            vcpu.LastExitMsrIndex, launchGuestCr3,
            launchHostCr3, launchCr3Metadata);
        return;
    }

    // keep each failure record below DbgPrintEx's 512-byte call limit so the
    // fields needed to identify a VMCS failure are not truncated
    const long vmcsSetupPhase = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsSetupPhase), 0, 0);
    const long vmcsCurrent = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.VmcsCurrent), 0, 0);
    const u64 probeResumeFlags = static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(
            const_cast<u64*>(&vcpu.FirstExitProbeResumeFlags)), 0, 0));
    const long probeReason = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.FirstExitProbeReason), 0, 0);
    const long probeAction = InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu.FirstExitProbeAction), 0, 0);
    u32 vmcsFailureCommit = 0;
    u32 vmcsFailureReason = 0;
    u64 vmcsFailureArg0 = 0;
    u64 vmcsFailureArg1 = 0;
    ReadVmcsFailureRecord(&vcpu, &vmcsFailureCommit, &vmcsFailureReason,
                          &vmcsFailureArg0, &vmcsFailureArg1);

    HV_PASSIVE_PRINT(
        "[HV] CPU %u launch failure: state=%ld stage=%ld check=%ld "
        "vmexits=%ld launch_flags=0x%llX raw_reason=0x%08X basic=%u "
        "entry_failure=%u probe=%ld probe_exits=%ld probe_resumes=%ld "
        "probe_reason=%ld probe_action=%ld action=%ld resumes=%ld\n",
        processorIndex, state, stage, checkStage, vmExitCount,
        vcpu.LastLaunchFlags, vcpu.LastExitReasonRaw,
        vcpu.LastExitReasonBasic, vcpu.LastExitEntryFailure,
        firstExitProbeState, firstExitProbeExits, firstExitProbeResumes,
        probeReason, probeAction, action, vcpu.VmResumeAttempts);
    HV_PASSIVE_PRINT(
        "[HV] CPU %u VMCS rejection: commit=%ld reason=%ld "
        "arg0=0x%llX arg1=0x%llX\n",
        processorIndex, vmcsFailureCommit, vmcsFailureReason,
        vmcsFailureArg0, vmcsFailureArg1);
    HV_PASSIVE_PRINT(
        "[HV] CPU %u descriptor/xstate diag: reject_mask=0x%X "
        "selectors=0x%llX/0x%llX gdt=0x%llX idt=0x%llX tss=0x%llX "
        "xsetbv=%ld xss_writes=%ld xss_rejects=%ld\n",
        processorIndex,
        static_cast<u32>(InterlockedCompareExchange(
            const_cast<volatile LONG*>(&vcpu.LaunchDescriptorRejectMask), 0, 0)),
        vcpu.LaunchDescriptorSelectorsLow, vcpu.LaunchDescriptorSelectorsHigh,
        vcpu.LaunchDescriptorGdtBase, vcpu.LaunchDescriptorIdtBase,
        vcpu.LaunchDescriptorTssBase,
        InterlockedCompareExchange(
            const_cast<volatile LONG*>(&vcpu.XsetbvExitCount), 0, 0),
        InterlockedCompareExchange(
            const_cast<volatile LONG*>(&vcpu.XssWriteExitCount), 0, 0),
        InterlockedCompareExchange(
            const_cast<volatile LONG*>(&vcpu.XssWriteRejectCount), 0, 0));
    HV_PASSIVE_PRINT(
        "[HV] CPU %u launch transition: msr=0x%08X msr_value=0x%llX "
        "rip=0x%llX rsp=0x%llX cr2=0x%llX exit_len=%llu "
        "qualification=0x%llX instrerr=0x%llX "
        "resume_flags=0x%llX probe_flags=0x%llX\n",
        processorIndex, vcpu.LastExitMsrIndex, vcpu.LastExitMsrValue,
        vcpu.LastGuestRip, vcpu.LastGuestRsp, vcpu.LastGuestCr2,
        vcpu.LastExitInstructionLength, vcpu.LastExitQualification,
        vcpu.LastVmInstructionError, vcpu.LastVmResumeFlags,
        probeResumeFlags);
    HV_PASSIVE_PRINT(
        "[HV] CPU %u VMCS access: setup_phase=%ld vmwrite_failed=%ld "
        "write_field=0x%llX write_flags=0x%llX write_error=0x%llX "
        "vmread_failed=%ld read_field=0x%llX read_flags=0x%llX "
        "read_error=0x%llX\n",
        processorIndex, vmcsSetupPhase, vmcsWriteFailed,
        vcpu.FirstVmcsWriteField, vcpu.FirstVmcsWriteFlags,
        vcpu.FirstVmcsWriteError, vmcsReadFailed, vcpu.FirstVmcsReadField,
        vcpu.FirstVmcsReadFlags, vcpu.FirstVmcsReadError);
    HV_PASSIVE_PRINT(
        "[HV] CPU %u VMCS image: mismatch=%ld field=0x%llX "
        "expected=0x%llX actual=0x%llX mask=0x%llX validity=0x%llX "
        "vmclear=0x%llX current=%ld vmptrld=0x%llX\n",
        processorIndex, vmcsValueMismatch, vcpu.FirstVmcsMismatchField,
        vcpu.FirstVmcsMismatchExpected, vcpu.FirstVmcsMismatchActual,
        vcpu.FirstVmcsMismatchMask, diagnosticValidity,
        vcpu.LastVmclearFlags, vmcsCurrent, vcpu.LastVmptrldFlags);
    HV_PASSIVE_PRINT(
        "[HV] CPU %u VMCS capabilities: primary=0x%llX tertiary=0x%llX "
        "cr3_raw_guest=0x%llX cr3_guest=0x%llX "
        "cr3_raw_host=0x%llX cr3_host=0x%llX cr3_meta=0x%llX\n",
        processorIndex, vcpu.PrimaryControlsCapability,
        vcpu.TertiaryControlsAllowed, launchRawGuestCr3, launchGuestCr3,
        launchRawHostCr3, launchHostCr3, launchCr3Metadata);
}

extern "C" NTSTATUS StartHypervisor() {
    if (g_HvImagePinned != 0 || g_VcpuData != nullptr ||
        g_HvTargetCpuWork != nullptr || g_HvTargetLaunchDpcWork != nullptr) {
        return STATUS_DEVICE_BUSY;
    }
    if (InterlockedCompareExchange(&g_HvLifecycle,
                                   kHvLifecycleStarting,
                                   kHvLifecycleIdle) != kHvLifecycleIdle) {
        return STATUS_DEVICE_BUSY;
    }
    auto rejectStart = [](NTSTATUS status) -> NTSTATUS {
        InterlockedCompareExchange(&g_HvLifecycle,
                                   kHvLifecycleIdle,
                                   kHvLifecycleStarting);
        ReleaseHvCrashBlob();
        return status;
    };
    // Keep this exported entry point safe even if a future caller bypasses
    // DriverEntry's initial gate.  The helper performs only read-only CPUID,
    // VMX capability, and IA32_FEATURE_CONTROL checks.
    if (!IsVmxSupported()) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected by the VMX capability gate\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    // a late-launch guest begins with interrupted Windows XSTATE, so each live
    // supervisor component must fit in the fixed preservation frame
    if (g_XsavesEnabled &&
        ((g_HostXssMask & ~g_XsavesMask) != 0 ||
         g_XsaveStateSize == 0 ||
         g_XsaveStateSize > VMEXIT_XSAVE_MAX ||
         g_XsaveStateSize > sizeof(GuestContext{}.FxArea))) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected: unsupported live XSS "
                 "host=0x%llX preserve=0x%llX frame=%lu\n",
                 g_HostXssMask, g_XsavesMask,
                 static_cast<ULONG>(g_XsaveStateSize));
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    HV_PASSIVE_PRINT("[HV] StartHypervisor: profile=0x%X CET_VMCS=%u XSAVES=%u\n",
             g_VmxCapabilityProfile, g_CetVmcsEnabled ? 1U : 0U,
             g_XsavesEnabled ? 1U : 0U);
    HV_PASSIVE_PRINT("[HV] late-launch baseline: cpuid=native "
                     "msr_bitmap=xss-guard cr0_mask=zero cr4_mask=zero "
                     "save_guest_efer_pat=1\n");

    int regs[4] = {};
    __cpuidex(regs, 0x80000000, 0);
    const u32 maxExtendedLeaf = static_cast<u32>(regs[0]);
    if (maxExtendedLeaf >= 0x80000008) {
        __cpuidex(regs, 0x80000008, 0);
        const u8 reportedLinearBits = static_cast<u8>((regs[0] >> 8) & 0xFF);
        if (reportedLinearBits >= 48 && reportedLinearBits <= 57) {
            g_LinearAddressBits = ((__readcr4() & CR4_LA57) &&
                                   reportedLinearBits >= 57) ? 57 : 48;
        }
    }

    RtlZeroMemory(regs, sizeof(regs));
    if (g_XstateMode == XstateSaveFxsave) {
        if (g_XsaveStateSize != FXSAVE_AREA_SIZE) {
            HV_PASSIVE_PRINT("[HV] FXSAVE contract has an invalid frame size: %lu\n",
                     static_cast<ULONG>(g_XsaveStateSize));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    } else if (g_XsavesEnabled) {
        // XSAVES uses the compacted XCR0|IA32_XSS layout.  CPUID.(D,1):EBX,
        // captured by the capability contract, is the bound that applies to
        // the VM-exit frame; leaf D.0:EBX only describes XCR0 state.
        u32 xsaveSize = g_XsaveStateSize;
        if (xsaveSize > VMEXIT_XSAVE_MAX ||
            xsaveSize > sizeof(GuestContext{}.FxArea)) {
            HV_PASSIVE_PRINT("[HV] XSAVES area too large: need %lu bytes, have %lu\n",
                     static_cast<ULONG>(xsaveSize),
                     static_cast<ULONG>(sizeof(GuestContext{}.FxArea)));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    } else {
        __cpuidex(regs, 0xD, 0);
        u32 xsaveSize = static_cast<u32>(regs[1]);
        if (xsaveSize > VMEXIT_XSAVE_MAX ||
            xsaveSize > sizeof(GuestContext{}.FxArea)) {
            HV_PASSIVE_PRINT("[HV] XSAVE area too large: need %lu bytes, have %lu\n",
                     static_cast<ULONG>(xsaveSize),
                     static_cast<ULONG>(sizeof(GuestContext{}.FxArea)));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    }

    __try {
        g_VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected: IA32_VMX_BASIC read faulted\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    // Honor the boot processor's VMX_BASIC address-width capability for the
    // allocation policy. Each launch callback independently rechecks its
    // local VMX_BASIC value; a heterogeneous package that requires a stricter
    // address width therefore fails closed before VMXON rather than entering
    // a partially valid run.
    g_VmxRequires32BitPhysicalAddress =
        (g_VmxBasic & VMX_BASIC_PHYSICAL_ADDRESS_32) != 0;
    const u64 vmxRegionSize = (g_VmxBasic >> 32) & 0x1FFFULL;
    if (((g_VmxBasic >> 50) & 0xFULL) != 6 ||
        vmxRegionSize == 0 || vmxRegionSize > PAGE_SIZE) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected: VMX_BASIC=0x%llX regionSize=0x%llX\n",
                 g_VmxBasic, vmxRegionSize);
        return rejectStart(STATUS_NOT_SUPPORTED);
    }

    // Capture a kernel/system CR3 while attached to the system process.  Do
    // not use the CR3 observed inside the per-CPU IPI callback: that callback
    // can interrupt a thread in an arbitrary user address space, and VMX
    // would then load a CR3 that cannot map the host VM-exit stack.
    KAPC_STATE apcState{};
    KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(PsInitialSystemProcess),
                         &apcState);
    g_HostCr3 = __readcr3();
    KeUnstackDetachProcess(&apcState);
    if ((g_HostCr3 & ~static_cast<u64>(PAGE_SIZE - 1)) == 0) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected: system CR3 is invalid (0x%llX)\n",
                 g_HostCr3);
        return rejectStart(STATUS_NOT_SUPPORTED);
    }

    RtlZeroMemory(&g_HvHostFaultRecord, sizeof(g_HvHostFaultRecord));

    g_ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (g_ProcessorCount == 0) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected: no active processors\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    if (!InitializeHvCrashBlob(g_ProcessorCount)) {
        HV_PASSIVE_PRINT("[HV] StartHypervisor rejected: failed to initialize crash blob\n");
        return rejectStart(STATUS_INSUFFICIENT_RESOURCES);
    }
    HV_PASSIVE_PRINT("[HV] StartHypervisor: processors=%u host_cr3=0x%llX "
             "vmx_basic=0x%llX xsave_frame=%lu\n", g_ProcessorCount,
             g_HostCr3, g_VmxBasic, static_cast<ULONG>(g_XsaveStateSize));

    g_VcpuData = static_cast<VcpuContext*>(
        ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(VcpuContext) * g_ProcessorCount, TAG_HV00)
    );

    if (!g_VcpuData) return rejectStart(STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(g_VcpuData, sizeof(VcpuContext) * g_ProcessorCount);
    g_HvTargetCpuWork = static_cast<TargetCpuWork*>(
        ExAllocatePoolWithTag(NonPagedPoolNx,
                              sizeof(TargetCpuWork) * g_ProcessorCount,
                              TAG_HV00));
    if (!g_HvTargetCpuWork) {
        StopHypervisorInternal(true);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_HvTargetCpuWork,
                  sizeof(TargetCpuWork) * g_ProcessorCount);
    g_HvTargetLaunchDpcWork = static_cast<TargetLaunchDpcWork*>(
        ExAllocatePoolWithTag(NonPagedPoolNx,
                              sizeof(TargetLaunchDpcWork) * g_ProcessorCount,
                              TAG_HV00));
    if (!g_HvTargetLaunchDpcWork) {
        StopHypervisorInternal(true);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_HvTargetLaunchDpcWork,
                  sizeof(TargetLaunchDpcWork) * g_ProcessorCount);

    for (u32 i = 0; i < g_ProcessorCount; i++) {
        g_VcpuData[i].VmxOnVirt     = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].VmxOnPhys);
        g_VcpuData[i].VmcsVirt      = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].VmcsPhys);
        g_VcpuData[i].MsrBitmapVirt = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].MsrBitmapPhys);
        if (g_VcpuData[i].MsrBitmapVirt) RtlZeroMemory(g_VcpuData[i].MsrBitmapVirt, PAGE_SIZE);

        g_VcpuData[i].HostStack = ExAllocatePoolWithTag(
            NonPagedPoolNx, kVmxHostStackSize, TAG_HVST);
        if (g_VcpuData[i].HostStack) {
            RtlZeroMemory(g_VcpuData[i].HostStack, kVmxHostStackSize);
            const u64 stackLastByte =
                reinterpret_cast<u64>(g_VcpuData[i].HostStack) +
                kVmxHostStackSize - 1;
            g_VcpuData[i].HostStackTop =
                stackLastByte & ~(kVmxHostStackAlignment - 1);
        }
        g_VcpuData[i].VmxHostIdt = ExAllocatePoolWithTag(
            NonPagedPoolNx, PAGE_SIZE, TAG_HVID);
        if (g_VcpuData[i].VmxHostIdt) {
            RtlZeroMemory(g_VcpuData[i].VmxHostIdt, PAGE_SIZE);
            g_VcpuData[i].VmxHostIdtBase =
                reinterpret_cast<u64>(g_VcpuData[i].VmxHostIdt);
        }
        g_VcpuData[i].TraceCapacity = HV_TRACE_RECORDS_PER_CPU;
        g_VcpuData[i].TraceRing = static_cast<HvTraceRecord*>(
            ExAllocatePoolWithTag(NonPagedPoolNx,
                                   sizeof(HvTraceRecord) *
                                       HV_TRACE_RECORDS_PER_CPU,
                                   TAG_HVTR));
        if (g_VcpuData[i].TraceRing) {
            RtlZeroMemory(g_VcpuData[i].TraceRing,
                          sizeof(HvTraceRecord) * HV_TRACE_RECORDS_PER_CPU);
        }

        if (!g_VcpuData[i].VmxOnVirt || !g_VcpuData[i].VmcsVirt ||
            !g_VcpuData[i].MsrBitmapVirt || !g_VcpuData[i].HostStack ||
            !g_VcpuData[i].VmxHostIdt || !g_VcpuData[i].TraceRing) {
                HV_PASSIVE_PRINT("[HV] CPU %u allocation failed: vmxon=%u vmcs=%u "
                          "msr_bitmap=%u host_stack=%u host_idt=%u trace_ring=%u\n", i,
                          g_VcpuData[i].VmxOnVirt ? 1U : 0U,
                          g_VcpuData[i].VmcsVirt ? 1U : 0U,
                          g_VcpuData[i].MsrBitmapVirt ? 1U : 0U,
                          g_VcpuData[i].HostStack ? 1U : 0U,
                          g_VcpuData[i].VmxHostIdt ? 1U : 0U,
                          g_VcpuData[i].TraceRing ? 1U : 0U);
                StopHypervisorInternal(true);
                ReleaseHvCrashBlob();
                return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    HV_PASSIVE_PRINT("[HV] allocations complete: processors=%u\n", g_ProcessorCount);

    // VMXON, the live Windows snapshot, guest XSS installation, and VMLAUNCH
    // remain in one callback per CPU. The save frame stays owned by the
    // interrupted DPC, matching HyperDbg even when staged startup is used.
    InterlockedExchange(&g_VmxGuestOptionalProfile,
                        0);
    InterlockedExchange(&g_VmxGuestOptionalProfileCandidate,
                        static_cast<LONG>(kGuestOptionalProfileMask));
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(
                              &g_HvVmxOffFailureFlagsAsm), 0);
    InterlockedExchange(&g_HvLaunchTelemetrySignature, 0x374C5648L);
    InterlockedExchange(&g_HvLaunchExpectedProcessors,
                        static_cast<LONG>(ExpectedLaunchProcessorCount()));
    InterlockedExchange(&g_HvLaunchProbeEntered, 0);
    InterlockedExchange(&g_HvLaunchProbeCompleted, 0);
    InterlockedExchange(&g_HvLaunchDispatchEntered, 0);
    InterlockedExchange(&g_HvLaunchAssemblyEntered, 0);
    InterlockedExchange(&g_HvLaunchPrepareEntered, 0);
    InterlockedExchange(&g_HvLaunchPrepareSucceeded, 0);
    InterlockedExchange(&g_HvLaunchGuestEntered, 0);
    InterlockedExchange(&g_HvLaunchVmlaunchIssued, 0);
    InterlockedExchange(&g_HvLaunchVmlaunchReturned, 0);
    InterlockedExchange(&g_HvLaunchGuestStarted, 0);
    InterlockedExchange(&g_HvLaunchMarkedLaunched, 0);
    InterlockedExchange(&g_HvLaunchVmExitAsmReached, 0);
    InterlockedExchange(&g_HvVmExitDebugHold, 0);
    InterlockedExchange(&g_HvLaunchFirstVmExitEntered, 0);
    InterlockedExchange(&g_HvLaunchDispatchReturned, 0);
    InterlockedExchange(&g_HvLaunchLastProbeProcessor, -1);
    InterlockedExchange(&g_HvLaunchLastDispatchProcessor, -1);
    InterlockedExchange(&g_HvLaunchLastPrepareProcessor, -1);
    InterlockedExchange(&g_HvLaunchLastReturnProcessor, -1);

    if (g_ProcessorCount == 0 ||
        (kDebugSingleCpu && kDebugCpuIndex >= g_ProcessorCount) ||
        (!kDebugSingleCpu && g_ProcessorCount < 2) ||
        (!kDebugSingleCpu && kReserveCoordinatorCpu &&
         kCoordinatorCpuIndex >= g_ProcessorCount)) {
        StopHypervisorInternal(true);
        return STATUS_NOT_SUPPORTED;
    }

    // keep the coordinator on the debugger-safe processor while the preflight
    // workers and staged launch callbacks are checked
    const u32 reservedProcessor = kCoordinatorCpuIndex;
    GROUP_AFFINITY coordinatorAffinity{};
    if (!BindCoordinatorToProcessor(reservedProcessor,
                                    &coordinatorAffinity)) {
        StopHypervisorInternal(true);
        return STATUS_INVALID_DEVICE_STATE;
    }
    bool coordinatorBound = true;
    bool unresolved = false;
    NTSTATUS targetStatus = STATUS_SUCCESS;

    if constexpr (kDebugSingleCpu) {
        const u32 debugCpu = kDebugCpuIndex;

        HV_PASSIVE_PRINT(
            "[HV] DEBUG single-CPU self-test: launching CPU %u only\n",
            debugCpu);

        targetStatus = QueueTargetLaunchDpc(debugCpu);

        if (NT_SUCCESS(targetStatus)) {
            const u64 debugDeadline =
                KeQueryInterruptTime() + kTargetOperationTimeout100ns;

            targetStatus = WaitTargetLaunchDpc(debugCpu,
                                               debugDeadline,
                                               &unresolved);
        }

        if (unresolved) {
            HV_PASSIVE_PRINT(
                "[HV] DEBUG single-CPU launch became unresolved\n");
            const NTSTATUS quarantineStatus = QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }

        const long debugState = InterlockedCompareExchange(
            &g_VcpuData[debugCpu].State, 0, 0);
        const long debugStage = InterlockedCompareExchange(
            &g_VcpuData[debugCpu].LaunchStage, 0, 0);

        HV_PASSIVE_PRINT(
            "[HV] DEBUG single-CPU result: cpu=%u status=0x%08X "
            "state=%ld stage=%ld "
            "vmlaunch_issued=%ld returned=%ld "
            "guest_started=%ld marked=%ld "
            "vmexit_asm=%ld first_vmexit=%ld\n",
            debugCpu,
            static_cast<ULONG>(targetStatus),
            debugState,
            debugStage,
            InterlockedCompareExchange(
                &g_HvLaunchVmlaunchIssued, 0, 0),
            InterlockedCompareExchange(
                &g_HvLaunchVmlaunchReturned, 0, 0),
            InterlockedCompareExchange(
                &g_HvLaunchGuestStarted, 0, 0),
            InterlockedCompareExchange(
                &g_HvLaunchMarkedLaunched, 0, 0),
            InterlockedCompareExchange(
                &g_HvLaunchVmExitAsmReached, 0, 0),
            InterlockedCompareExchange(
                &g_HvLaunchFirstVmExitEntered, 0, 0));

        if (!NT_SUCCESS(targetStatus) ||
            debugState != VcpuLaunched) {

            HV_PASSIVE_PRINT(
                "[HV] DEBUG single-CPU VMLAUNCH path failed; rolling back\n");
            PrintLaunchResult(debugCpu, g_VcpuData[debugCpu]);

            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return STATUS_NOT_SUPPORTED;
        }

        // the launch DPC and its private CPUID probe have returned. run a
        // second CPUID from a normal system thread that is scheduled onto CPU1.
        // this is the first test that crosses the exact boundary implicated by
        // the V44 log: DPC return -> normal scheduler context -> VM-exit.
        HV_PASSIVE_PRINT(
            "[HV] DEBUG single-CPU launch returned; "
            "queueing post-DPC runtime canary on CPU %u\n",
            debugCpu);

        targetStatus =
            QueueTargetOperation(debugCpu, TargetOperationRuntimeCanary);
        if (NT_SUCCESS(targetStatus)) {
            const u64 canaryDeadline =
                KeQueryInterruptTime() + kTargetOperationTimeout100ns;
            targetStatus =
                WaitTargetOperation(debugCpu, canaryDeadline, &unresolved);
        }

        TargetCpuWork* canaryWork = &g_HvTargetCpuWork[debugCpu];
        HV_PASSIVE_PRINT(
            "[HV] DEBUG post-DPC canary: cpu=%u status=0x%08X "
            "worker_state=%ld irql=%ld vmexits=%ld->%ld "
            "resumes=%ld->%ld reason=%ld cpuid=%08X-%08X-%08X-%08X "
            "cr3=0x%llX cr4=0x%llX\n",
            debugCpu,
            static_cast<ULONG>(targetStatus),
            InterlockedCompareExchange(&canaryWork->State, 0, 0),
            InterlockedCompareExchange(&canaryWork->CanaryIrql, 0, 0),
            InterlockedCompareExchange(
                &canaryWork->CanaryBaselineVmExits, 0, 0),
            InterlockedCompareExchange(
                &canaryWork->CanaryObservedVmExits, 0, 0),
            InterlockedCompareExchange(
                &canaryWork->CanaryBaselineVmResumes, 0, 0),
            InterlockedCompareExchange(
                &canaryWork->CanaryObservedVmResumes, 0, 0),
            InterlockedCompareExchange(
                &canaryWork->CanaryLastExitReason, 0, 0),
            canaryWork->CanaryCpuidEax,
            canaryWork->CanaryCpuidEbx,
            canaryWork->CanaryCpuidEcx,
            canaryWork->CanaryCpuidEdx,
            canaryWork->CanaryCr3,
            canaryWork->CanaryCr4);

        if (unresolved) {
            HV_PASSIVE_PRINT(
                "[HV] DEBUG post-DPC canary became unresolved; "
                "quarantining VMX image\n");
            const NTSTATUS quarantineStatus =
                QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }

        if (!NT_SUCCESS(targetStatus)) {
            HV_PASSIVE_PRINT(
                "[HV] DEBUG post-DPC canary failed; retaining detailed "
                "target CPU launch/exit evidence\n");
            PrintLaunchResult(debugCpu, g_VcpuData[debugCpu]);
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return targetStatus;
        }

        const ULONG candidateOptionalProfile =
            static_cast<ULONG>(InterlockedCompareExchange(
                &g_VmxGuestOptionalProfileCandidate, 0, 0));
        if (KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) !=
            g_ProcessorCount) {
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }

        InterlockedExchange(
            &g_VmxGuestOptionalProfile,
            static_cast<LONG>(candidateOptionalProfile));
        InterlockedExchange(&g_HvLifecycle, kHvLifecycleRunning);

        HV_PASSIVE_PRINT(
            "[HV] DEBUG single-CPU runtime contract passed: cpu=%u "
            "vmexits=%ld resumes=%ld waitpkg_ctl=%ld\n",
            debugCpu,
            InterlockedCompareExchange(
                &g_VcpuData[debugCpu].VmExitCount, 0, 0),
            InterlockedCompareExchange(
                &g_VcpuData[debugCpu].VmResumeAttempts, 0, 0),
            InterlockedCompareExchange(&g_HvWaitpkgVmcsEnabled, 0, 0));

        const NTSTATUS watchdogStatus = StartRuntimeWatchdog(debugCpu);
        HV_PASSIVE_PRINT(
            "[HV] native watchdog start: target_cpu=%u observer_cpu=%u "
            "status=0x%08X poll_ms=10 print_ms=500 "
            "break_on=vmx_abort/xss_reject/vmresume/fatal/hostfault/triple\n",
            debugCpu, kCoordinatorCpuIndex,
            static_cast<ULONG>(watchdogStatus));

        ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                    &coordinatorBound);
        return STATUS_SUCCESS;
    }

    HV_PASSIVE_PRINT(
        "[HV] ALLCPU staged bring-up: processors=%u coordinator=%u "
        "launch=target-dpc first_exit_probe=%u post_dpc_canary=1 "
        "final_canary_sweep=1\n",
        g_ProcessorCount, kCoordinatorCpuIndex,
        kEnableLaunchFirstExitProbe ? 1U : 0U);

    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        const NTSTATUS queueStatus =
            QueueTargetOperation(i, TargetOperationProbe);
        if (!NT_SUCCESS(queueStatus) && NT_SUCCESS(targetStatus)) {
            targetStatus = queueStatus;
        }
    }
    u64 deadline = KeQueryInterruptTime() + kTargetOperationTimeout100ns;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        if (g_HvTargetCpuWork[i].ThreadHandle == nullptr) continue;
        const NTSTATUS waitStatus =
            WaitTargetOperation(i, deadline, &unresolved);
        if (!NT_SUCCESS(waitStatus) && NT_SUCCESS(targetStatus)) {
            targetStatus = waitStatus;
        }
    }
    if (unresolved) {
        const NTSTATUS quarantineStatus = QuarantineUnresolvedTargetWork();
        ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                    &coordinatorBound);
        return quarantineStatus;
    }
    if (!NT_SUCCESS(targetStatus)) {
        StopHypervisorInternal(true);
        ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                    &coordinatorBound);
        return targetStatus;
    }
    InterlockedExchange(&g_HvLaunchProbeCompleted, 1);

    const u32 expected = ExpectedLaunchProcessorCount();
    u32 launchedCount = 0;

    if constexpr (kUseHyperDbgGenericLaunch) {
        // this is the upstream HyperDbg broadcast shape retained for controlled
        // comparison, but it has no timeout when a CPU does not return
        // from VM-entry or the first VM-exit
        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        HV_PASSIVE_PRINT(
            "[HV] launching all processors through KeGenericCallDpc\n");
        KeGenericCallDpc(HyperDbgLaunchDpcRoutine, nullptr);

        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            const long state = InterlockedCompareExchange(
                &g_VcpuData[i].State, 0, 0);
            const long stage = InterlockedCompareExchange(
                &g_VcpuData[i].LaunchStage, 0, 0);
            const long checkStage = InterlockedCompareExchange(
                &g_VcpuData[i].LaunchCheckStage, 0, 0);
            const long vmExitCount = InterlockedCompareExchange(
                &g_VcpuData[i].VmExitCount, 0, 0);
            if (state == VcpuLaunched) ++launchedCount;
            HV_VERBOSE_PRINT(
                "[HV] CPU %u generic DPC launch result: state=%ld stage=%ld "
                "check=%ld vmexits=%ld asm=%ld issued=%ld returned=%ld "
                "started=%ld vmexit_asm=%ld first_vmexit=%ld "
                "dispatch_returned=%ld launch_flags=0x%llX "
                "instrerr=0x%llX\n",
                i, state, stage, checkStage, vmExitCount,
                InterlockedCompareExchange(&g_HvLaunchAssemblyEntered, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchVmlaunchIssued, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchVmlaunchReturned, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchGuestStarted, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchVmExitAsmReached, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchFirstVmExitEntered, 0,
                                           0),
                InterlockedCompareExchange(&g_HvLaunchDispatchReturned, 0,
                                           0),
                g_VcpuData[i].LastLaunchFlags,
                g_VcpuData[i].LastVmInstructionError);
        }
        HV_PASSIVE_PRINT(
            "[HV] generic DPC launch completed: %u/%u processors\n",
            launchedCount, expected);
    } else {
        // launch one processor at a time to keep the coordinator alive, give
        // every target a finite completion deadline, and preserve per-CPU
        // failure state when VM-entry or VM-exit cannot return
        HV_PASSIVE_PRINT(
            "[HV] launching processors through staged target DPCs: "
            "coordinator=%u timeout_ms=%llu\n",
            reservedProcessor,
            kTargetOperationTimeout100ns / 10000ULL);

        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (i == reservedProcessor) continue;
            const NTSTATUS queueStatus = QueueTargetLaunchDpc(i);
            if (!NT_SUCCESS(queueStatus)) {
                targetStatus = queueStatus;
                break;
            }
            const u64 launchDeadline =
                KeQueryInterruptTime() + kTargetOperationTimeout100ns;
            const NTSTATUS waitStatus =
                WaitTargetLaunchDpc(i, launchDeadline, &unresolved);
            const long state = InterlockedCompareExchange(
                &g_VcpuData[i].State, 0, 0);
            if (!NT_SUCCESS(waitStatus) ||
                LaunchResultNeedsDetail(i, g_VcpuData[i])) {
                const long stage = InterlockedCompareExchange(
                    &g_VcpuData[i].LaunchStage, 0, 0);
                const long checkStage = InterlockedCompareExchange(
                    &g_VcpuData[i].LaunchCheckStage, 0, 0);
                const long vmExitCount = InterlockedCompareExchange(
                    &g_VcpuData[i].VmExitCount, 0, 0);
                const long firstExitProbeState =
                    ReadFirstExitProbeState(&g_VcpuData[i]);
                const long firstExitProbeExits = InterlockedCompareExchange(
                    &g_VcpuData[i].FirstExitProbeObservedVmExits, 0, 0);
                const long firstExitProbeResumes = InterlockedCompareExchange(
                    &g_VcpuData[i].FirstExitProbeObservedVmResumes, 0, 0);
                const long action = InterlockedCompareExchange(
                    &g_VcpuData[i].LastExitAction, 0, 0);
                const u64 launchRawGuestCr3 =
                    ReadLaunchCr3Field(&g_VcpuData[i].LaunchRawGuestCr3);
                const u64 launchGuestCr3 =
                    ReadLaunchCr3Field(&g_VcpuData[i].LaunchGuestCr3);
                const u64 launchRawHostCr3 =
                    ReadLaunchCr3Field(&g_VcpuData[i].LaunchRawHostCr3);
                const u64 launchHostCr3 =
                    ReadLaunchCr3Field(&g_VcpuData[i].LaunchHostCr3);
                const u64 launchCr3Metadata =
                    ReadLaunchCr3Field(&g_VcpuData[i].LaunchCr3Metadata);
                HV_PASSIVE_PRINT(
                    "[HV] CPU %u staged launch: status=0x%08X state=%ld "
                    "stage=%ld check=%ld vmexits=%ld raw_reason=0x%08X "
                    "basic=%u msr=0x%08X msr_value=0x%llX exit_len=%llu "
                    "probe=%ld probe_exits=%ld probe_resumes=%ld "
                    "probe_reason=%ld probe_action=%ld action=%ld "
                    "resume_flags=0x%llX rip=0x%llX rsp=0x%llX "
                    "flags=0x%llX instrerr=0x%llX "
                    "cr3_guest=0x%llX cr3_host=0x%llX cr3_meta=0x%llX\n",
                    i, static_cast<ULONG>(waitStatus), state, stage, checkStage,
                    vmExitCount,
                    g_VcpuData[i].LastExitReasonRaw,
                    g_VcpuData[i].LastExitReasonBasic,
                    g_VcpuData[i].LastExitMsrIndex,
                    g_VcpuData[i].LastExitMsrValue,
                    g_VcpuData[i].LastExitInstructionLength,
                    firstExitProbeState,
                    firstExitProbeExits,
                    firstExitProbeResumes,
                    InterlockedCompareExchange(
                        &g_VcpuData[i].FirstExitProbeReason, 0, 0),
                    InterlockedCompareExchange(
                        &g_VcpuData[i].FirstExitProbeAction, 0, 0),
                    action,
                    g_VcpuData[i].LastVmResumeFlags,
                    g_VcpuData[i].LastGuestRip,
                    g_VcpuData[i].LastGuestRsp,
                    g_VcpuData[i].LastLaunchFlags,
                    g_VcpuData[i].LastVmInstructionError,
                    launchGuestCr3, launchHostCr3, launchCr3Metadata);
                // keep raw CR3 values in a separate short record because the
                // detailed launch line is close to DbgPrintEx's 512-byte limit
                HV_PASSIVE_PRINT(
                    "[HV] CPU %u staged CR3: raw_guest=0x%llX guest=0x%llX "
                    "raw_host=0x%llX host=0x%llX meta=0x%llX\n",
                    i, launchRawGuestCr3, launchGuestCr3, launchRawHostCr3,
                    launchHostCr3, launchCr3Metadata);
            }
            if (!NT_SUCCESS(waitStatus)) {
                targetStatus = waitStatus;
                break;
            }
            if (state != VcpuLaunched) {
                targetStatus = STATUS_NOT_SUPPORTED;
                break;
            }

            ++launchedCount;

            // Do not propagate VMX to the next processor until this CPU has
            // returned from its launch DPC, entered ordinary scheduler
            // context, completed another CPUID VM-exit, and resumed cleanly.
            const NTSTATUS canaryStatus =
                RunRuntimeCanary(i, "staged post-DPC", &unresolved);
            if (unresolved) {
                targetStatus = canaryStatus;
                break;
            }
            if (!NT_SUCCESS(canaryStatus)) {
                targetStatus = canaryStatus;
                PrintLaunchResult(i, g_VcpuData[i]);
                break;
            }
        }

        if (NT_SUCCESS(targetStatus) && !unresolved) {
            const u32 stagedExpected =
                expected - (kReserveCoordinatorCpu ? 1U : 0U);
            u32 firstExitReturned = 0;
            u64 totalVmExits = 0;
            for (u32 i = 0; i < g_ProcessorCount; ++i) {
                if (i == reservedProcessor) continue;
                if (ReadFirstExitProbeState(&g_VcpuData[i]) ==
                    FirstExitProbeReturned) {
                    ++firstExitReturned;
                }
                totalVmExits += static_cast<u64>(InterlockedCompareExchange(
                    &g_VcpuData[i].VmExitCount, 0, 0));
            }
            HV_PASSIVE_PRINT(
                "[HV] staged non-coordinator launch completed: "
                "%u/%u processors first_exit=%u/%u total_vmexits=%llu "
                "vmexit_asm=%ld first_vmexit=%ld\n",
                launchedCount, stagedExpected,
                firstExitReturned, stagedExpected, totalVmExits,
                InterlockedCompareExchange(&g_HvLaunchVmExitAsmReached, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchFirstVmExitEntered, 0, 0));
        } else {
            HV_PASSIVE_PRINT(
                "[HV] staged launch stopped: status=0x%08X launched=%u/%u "
                "unresolved=%u\n",
                static_cast<ULONG>(targetStatus), launchedCount, expected,
                unresolved ? 1U : 0U);
        }

        if (unresolved) {
            const NTSTATUS quarantineStatus =
                QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }
        if (!NT_SUCCESS(targetStatus)) {
            if (!unresolved) {
                for (u32 i = 0; i < g_ProcessorCount; ++i) {
                    if (LaunchResultNeedsDetail(i, g_VcpuData[i])) {
                        PrintLaunchResult(i, g_VcpuData[i]);
                    }
                }
            }
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return targetStatus;
        }

        // Every non-coordinator CPU has now crossed both the launch DPC and a
        // normal scheduler-context VM-exit. Move the startup thread away from
        // CPU0 before virtualizing CPU0 itself; this avoids waiting for a DPC
        // on the same processor that owns the startup transaction.
        u32 handoffProcessor = MAXULONG;
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (i == reservedProcessor) continue;
            if (InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0) ==
                    VcpuLaunched &&
                ReadFirstExitProbeState(&g_VcpuData[i]) ==
                    FirstExitProbeReturned) {
                handoffProcessor = i;
                break;
            }
        }

        if (handoffProcessor == MAXULONG) {
            HV_PASSIVE_PRINT(
                "[HV] all-core handoff failed: no verified VMX CPU available\n");
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return STATUS_NOT_SUPPORTED;
        }

        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        if (!BindCoordinatorToProcessor(handoffProcessor,
                                        &coordinatorAffinity)) {
            HV_PASSIVE_PRINT(
                "[HV] all-core handoff failed: cannot bind startup thread "
                "to verified CPU %u\n",
                handoffProcessor);
            StopHypervisorInternal(true);
            return STATUS_INVALID_DEVICE_STATE;
        }
        coordinatorBound = true;

        HV_PASSIVE_PRINT(
            "[HV] all-core handoff: startup thread moved to verified CPU %u; "
            "launching coordinator CPU %u last\n",
            handoffProcessor, reservedProcessor);

        targetStatus = QueueTargetLaunchDpc(reservedProcessor);
        if (NT_SUCCESS(targetStatus)) {
            const u64 coordinatorDeadline =
                KeQueryInterruptTime() + kTargetOperationTimeout100ns;
            targetStatus =
                WaitTargetLaunchDpc(reservedProcessor,
                                    coordinatorDeadline,
                                    &unresolved);
        }

        const long coordinatorState = InterlockedCompareExchange(
            &g_VcpuData[reservedProcessor].State, 0, 0);

        if (unresolved) {
            HV_PASSIVE_PRINT(
                "[HV] coordinator CPU %u launch became unresolved; "
                "quarantining VMX image\n",
                reservedProcessor);
            const NTSTATUS quarantineStatus =
                QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }

        if (!NT_SUCCESS(targetStatus) ||
            coordinatorState != VcpuLaunched) {
            HV_PASSIVE_PRINT(
                "[HV] coordinator CPU %u launch failed: "
                "status=0x%08X state=%ld\n",
                reservedProcessor,
                static_cast<ULONG>(targetStatus),
                coordinatorState);
            PrintLaunchResult(reservedProcessor,
                              g_VcpuData[reservedProcessor]);
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return NT_SUCCESS(targetStatus) ? STATUS_NOT_SUPPORTED
                                            : targetStatus;
        }

        ++launchedCount;

        targetStatus =
            RunRuntimeCanary(reservedProcessor,
                             "coordinator post-DPC",
                             &unresolved);
        if (unresolved) {
            HV_PASSIVE_PRINT(
                "[HV] coordinator CPU %u runtime canary became unresolved; "
                "quarantining VMX image\n",
                reservedProcessor);
            const NTSTATUS quarantineStatus =
                QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }
        if (!NT_SUCCESS(targetStatus)) {
            HV_PASSIVE_PRINT(
                "[HV] coordinator CPU %u runtime canary failed\n",
                reservedProcessor);
            PrintLaunchResult(reservedProcessor,
                              g_VcpuData[reservedProcessor]);
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return targetStatus;
        }

        // All logical processors are now in VMX non-root. Re-test every CPU in
        // the final topology before publishing the lifecycle as Running. This
        // catches failures that only appear once the last native coordinator is
        // gone and proves another clean CPUID VM-exit/VMRESUME on each CPU.
        HV_PASSIVE_PRINT(
            "[HV] all %u processors launched; running final per-CPU "
            "runtime canary sweep\n",
            expected);

        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            targetStatus =
                RunRuntimeCanary(i, "all-core final", &unresolved);
            if (unresolved) {
                HV_PASSIVE_PRINT(
                    "[HV] final canary sweep became unresolved on CPU %u; "
                    "quarantining VMX image\n",
                    i);
                const NTSTATUS quarantineStatus =
                    QuarantineUnresolvedTargetWork();
                ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                            &coordinatorBound);
                return quarantineStatus;
            }
            if (!NT_SUCCESS(targetStatus)) {
                HV_PASSIVE_PRINT(
                    "[HV] final canary sweep failed on CPU %u: "
                    "status=0x%08X\n",
                    i, static_cast<ULONG>(targetStatus));
                PrintLaunchResult(i, g_VcpuData[i]);
                StopHypervisorInternal(true);
                ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                            &coordinatorBound);
                return targetStatus;
            }
        }

        u32 fullFirstExitReturned = 0;
        u64 fullVmExits = 0;
        u64 fullVmResumes = 0;
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (ReadFirstExitProbeState(&g_VcpuData[i]) ==
                FirstExitProbeReturned) {
                ++fullFirstExitReturned;
            }
            fullVmExits += static_cast<u64>(InterlockedCompareExchange(
                &g_VcpuData[i].VmExitCount, 0, 0));
            fullVmResumes += static_cast<u64>(InterlockedCompareExchange(
                &g_VcpuData[i].VmResumeAttempts, 0, 0));
        }

        HV_PASSIVE_PRINT(
            "[HV] all-core runtime contract passed: launched=%u/%u "
            "first_exit=%u/%u total_vmexits=%llu total_resumes=%llu\n",
            launchedCount, expected,
            fullFirstExitReturned, expected,
            fullVmExits, fullVmResumes);
    }

    if (launchedCount != expected) {
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (LaunchResultNeedsDetail(i, g_VcpuData[i])) {
                PrintLaunchResult(i, g_VcpuData[i]);
            }
        }
        StopHypervisorInternal(true);
        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        return IsHypervisorQuarantined() ? STATUS_SUCCESS
                                         : STATUS_NOT_SUPPORTED;
    }

    const ULONG candidateOptionalProfile =
        static_cast<ULONG>(InterlockedCompareExchange(
            &g_VmxGuestOptionalProfileCandidate, 0, 0));

    u32 ok = 0;

    for (u32 i = 0; i < g_ProcessorCount; i++) {
        const long state = InterlockedCompareExchange(
            &g_VcpuData[i].State, 0, 0);
        if (state == VcpuLaunched) {
            ok++;
        }
        if (LaunchResultNeedsDetail(i, g_VcpuData[i])) {
            PrintLaunchResult(i, g_VcpuData[i]);
        }
    }

    if (ok != expected) {
        HV_VERBOSE_PRINT("[HV] StartHypervisor rejected: only %u/%u expected processors entered VMX\n",
                         ok, expected);

        StopHypervisorInternal(true);
        ReleaseHvCrashBlob();
        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        return STATUS_NOT_SUPPORTED;
    }

    if (KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) !=
        g_ProcessorCount) {
        StopHypervisorInternal(true);
        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        return IsHypervisorQuarantined() ? STATUS_SUCCESS
                                         : STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    // The synchronized launch completed on every logical processor.
    // Publish the reduced profile only after that point, so guest CPUID never
    // changes while a CPU is still preparing its VMCS.
    InterlockedExchange(&g_VmxGuestOptionalProfile,
                        static_cast<LONG>(candidateOptionalProfile));

    InterlockedExchange(&g_HvLifecycle, kHvLifecycleRunning);
    ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
    return STATUS_SUCCESS;
}

static bool HasParkedVcpu() {
    if (!g_VcpuData) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        const long state =
            InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
        if (state == VcpuParked) return true;
    }
    return false;
}

static bool HasLiveVcpu() {
    if (!g_VcpuData) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        const long state =
            InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
        if (state == VcpuLaunched || state == VcpuVmxOn ||
            state == VcpuStarting || state == VcpuTearingDown ||
            state == VcpuParked) {
            return true;
        }
    }
    return false;
}

// A failed launch can still leave VMX active when control returned through an
// exception or an unexpected assembly path. Treat every non-terminal state as
// live so teardown never frees a VMCS or host stack that hardware may use.
static bool HasUnresolvedVcpu() {
    if (!g_VcpuData) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        const long state =
            InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
        const long stage =
            InterlockedCompareExchange(&g_VcpuData[i].LaunchStage, 0, 0);
        if (state == VcpuFailed && stage >= LaunchStageReady &&
            stage < LaunchStageAbort) {
            // A failed marker before AbortHvLaunch can still be reached while
            // the processor remains in VMX non-root operation.
            return true;
        }
        if (state != VcpuStopped && state != VcpuFailed &&
            state != VcpuUninitialized) {
            return true;
        }
    }
    return false;
}

// never reclaim a VMCS while its owner still reports hardware ownership or a
// failed clear. A terminal lifecycle value alone is not sufficient evidence
// that VMX root has released the current VMCS
static bool HasUnclearedVmcs() {
    if (!g_VcpuData) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        const long vmcsState = InterlockedCompareExchange(
            &g_VcpuData[i].VmcsCurrent, 0, 0);
        if (vmcsState != VmcsCurrentStateNone) return true;
    }
    return false;
}

// A parked processor has no architecturally valid guest continuation and may
// still execute the VM-exit image. Pin the driver object once, retain all VMX
// allocations, and return to the caller instead of blocking an unload thread.
static void PinImageForParkedCpu() {
    if (!g_HvDriverObject ||
        InterlockedCompareExchange(&g_HvImagePinned, 1, 0) != 0) {
        return;
    }
    ObReferenceObject(g_HvDriverObject);
    HV_VERBOSE_PRINT("[HV] parked CPU quarantined; driver image pinned\n");
}

static void StopHypervisorInternal(bool startRollback) {
    const LONG expected = startRollback ? kHvLifecycleStarting
                                        : kHvLifecycleRunning;
    if (InterlockedCompareExchange(&g_HvLifecycle,
                                   kHvLifecycleStopping,
                                   expected) != expected) {
        // Only the start owner or the single public stop owner may tear down
        // VMX state. Concurrent callers leave the owner's rendezvous intact.
        return;
    }

    StopRuntimeWatchdog();

    if (!g_VcpuData) {
        g_ProcessorCount = 0;
        g_HostCr3 = 0;
        g_VmxBasic = 0;
        g_VmxRequires32BitPhysicalAddress = false;
        InterlockedExchange(&g_HvLifecycle, kHvLifecycleIdle);
        return;
    }

    // A parked CPU has no native continuation. Keep all code and VMX storage
    // resident until a debugger or reboot removes the quarantine.
    if (HasParkedVcpu()) {
        PinImageForParkedCpu();
        InterlockedExchange(&g_HvLifecycle, kHvLifecycleQuarantined);
        return;
    }

    if (HasUnresolvedTargetWork()) {
        PinImageForParkedCpu();
        InterlockedExchange(&g_HvLifecycle, kHvLifecycleQuarantined);
        return;
    }

    u32 reservedProcessor = CurrentProcessorIndex();
    if (reservedProcessor >= g_ProcessorCount) reservedProcessor = 0;
    GROUP_AFFINITY coordinatorAffinity{};
    bool coordinatorBound =
        BindCoordinatorToProcessor(reservedProcessor, &coordinatorAffinity);
    bool unresolved = false;
    bool stopFailed = !coordinatorBound;

    if (coordinatorBound) {
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (i == reservedProcessor) continue;
            const long state =
                InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
            if (state != VcpuLaunched && state != VcpuVmxOn) continue;
            if (!NT_SUCCESS(QueueTargetOperation(i, TargetOperationStop))) {
                stopFailed = true;
            }
        }

        const u64 deadline =
            KeQueryInterruptTime() + kTargetOperationTimeout100ns;
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (i == reservedProcessor ||
                !g_HvTargetCpuWork ||
                g_HvTargetCpuWork[i].ThreadHandle == nullptr) {
                continue;
            }
            if (!NT_SUCCESS(WaitTargetOperation(i, deadline, &unresolved))) {
                stopFailed = true;
            }
        }
        KeRevertToUserGroupAffinityThread(&coordinatorAffinity);
        coordinatorBound = false;
    }

    const long reservedState = InterlockedCompareExchange(
        &g_VcpuData[reservedProcessor].State, 0, 0);
    if (!unresolved &&
        (reservedState == VcpuLaunched || reservedState == VcpuVmxOn)) {
        u32 nativeProcessor = MAXULONG;
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            const long candidateState =
                InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
            if (i != reservedProcessor &&
                IsVcpuStopTerminal(candidateState)) {
                nativeProcessor = i;
                break;
            }
        }
        GROUP_AFFINITY finalAffinity{};
        if (nativeProcessor == MAXULONG ||
            !BindCoordinatorToProcessor(nativeProcessor, &finalAffinity)) {
            stopFailed = true;
        } else {
            coordinatorBound = true;
            NTSTATUS status = QueueTargetOperation(reservedProcessor,
                                                   TargetOperationStop);
            if (NT_SUCCESS(status)) {
                const u64 deadline =
                    KeQueryInterruptTime() + kTargetOperationTimeout100ns;
                status = WaitTargetOperation(reservedProcessor,
                                             deadline,
                                             &unresolved);
            }
            if (!NT_SUCCESS(status)) stopFailed = true;
            KeRevertToUserGroupAffinityThread(&finalAffinity);
            coordinatorBound = false;
        }
    }

    if (coordinatorBound) {
        KeRevertToUserGroupAffinityThread(&coordinatorAffinity);
    }

    if (unresolved || stopFailed || HasParkedVcpu() || HasLiveVcpu() ||
        HasUnresolvedVcpu() || HasUnclearedVmcs() ||
        HasUnresolvedTargetWork()) {
        PinImageForParkedCpu();
        InterlockedExchange(&g_HvLifecycle, kHvLifecycleQuarantined);
        return;
    }

    for (u32 i = 0; i < g_ProcessorCount; i++) {
        if (startRollback) {
            WriteHvTrace(&g_VcpuData[i], i, HvTraceEventRollbackDone);
        }
        if (g_VcpuData[i].VmxOnVirt) {
            MmFreeContiguousMemory(g_VcpuData[i].VmxOnVirt);
        }
        if (g_VcpuData[i].VmcsVirt) {
            MmFreeContiguousMemory(g_VcpuData[i].VmcsVirt);
        }
        if (g_VcpuData[i].MsrBitmapVirt) {
            MmFreeContiguousMemory(g_VcpuData[i].MsrBitmapVirt);
        }
        if (g_VcpuData[i].HostStack) {
            ExFreePoolWithTag(g_VcpuData[i].HostStack, TAG_HVST);
        }
        if (g_VcpuData[i].VmxHostIdt) {
            ExFreePoolWithTag(g_VcpuData[i].VmxHostIdt, TAG_HVID);
        }
        if (g_VcpuData[i].TraceRing) {
            ExFreePoolWithTag(g_VcpuData[i].TraceRing, TAG_HVTR);
        }
    }
    if (g_HvTargetCpuWork) {
        ExFreePoolWithTag(g_HvTargetCpuWork, TAG_HV00);
        g_HvTargetCpuWork = nullptr;
    }
    if (g_HvTargetLaunchDpcWork) {
        ExFreePoolWithTag(g_HvTargetLaunchDpcWork, TAG_HV00);
        g_HvTargetLaunchDpcWork = nullptr;
    }
    ExFreePoolWithTag(g_VcpuData, TAG_HV00);
    g_VcpuData = nullptr;
    g_ProcessorCount = 0;
    g_HostCr3 = 0;
    g_VmxBasic = 0;
    g_VmxRequires32BitPhysicalAddress = false;
    ReleaseHvCrashBlob();
    InterlockedExchange(&g_HvLifecycle, kHvLifecycleIdle);
}

extern "C" void StopHypervisor() {
    StopHypervisorInternal(false);
}

extern "C" bool IsHypervisorStopComplete() {
    const LONG lifecycle =
        InterlockedCompareExchange(&g_HvLifecycle, 0, 0);
    if (lifecycle != kHvLifecycleIdle) return false;
    MemoryBarrier();
    return g_VcpuData == nullptr &&
           InterlockedCompareExchange(&g_HvImagePinned, 0, 0) == 0;
}

extern "C" bool IsHypervisorQuarantined() {
    return InterlockedCompareExchange(&g_HvLifecycle, 0, 0) ==
               kHvLifecycleQuarantined ||
           InterlockedCompareExchange(&g_HvImagePinned, 0, 0) != 0;
}

extern "C" void QuarantineHypervisorImage() {
    if (!g_VcpuData) return;
    PinImageForParkedCpu();
    if (g_HvDriverObject) g_HvDriverObject->DriverUnload = nullptr;
    InterlockedExchange(&g_HvLifecycle, kHvLifecycleQuarantined);
}
