#pragma once

// Internal interface shared by the VMX implementation units.  Keeping this
// boundary small makes it possible to change one lifecycle stage without
// pulling the complete driver into every source file.

#include <intrin.h>
#include <ntifs.h>

#include "common.h"
#include "knhv_logging.h"
#include "vmx.h"
#include "vmx_contract.h"

#ifndef KNHV_BUILD_ID
#define KNHV_BUILD_ID 0
#endif

// Assembly entry points and the fixed-frame callbacks use C linkage because
// their names are part of the MASM ABI.
extern "C" {
u64 HvVmxOn(u64* physical_address);
void HvVmxOff();
u64 HvVmClear(u64* physical_address);
u64 HvVmPtrSt(u64* physical_address);
u64 HvVmPtrLd(u64* physical_address);
u64 HvVmWrite(u64 field, u64 value);
u64 HvVmReadChecked(u64 field, u64* value);

u64 HvLaunchGuest();
void HvRestoreStateAndReturn(GuestContext* context);
void GuestStartThunk();
void HvCall(u64 magic, u64 command, u64 arg1, u64 arg2);
void HvVmExitEntryPoint();

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

void HvTraceCurrentVcpuEvent(u32 event);
bool HvFaultInjectedCurrent(u32 stage);
void HvCaptureFatalSnapshotPreVmxoff(GuestContext* context);

u16 GetCs();
u16 GetDs();
u16 GetEs();
u16 GetSs();
u16 GetFs();
u16 GetGs();
u16 GetTr();
u16 GetLdtr();
u64 GetGdtBase();
u16 GetGdtLimit();
u64 GetIdtBase();
u16 GetIdtLimit();
u64 GetRflags();
u64 GetDr7();
u32 HvGetSegmentLimit(u16 selector);
u32 HvGetSegmentAr(u16 selector);

ULONG_PTR EnableHvCallback(ULONG_PTR context);
ULONG PrepareHvCallback(ULONG_PTR context, void* guest_stack,
                        void* guest_ip);
void AbortHvLaunch(u64 rflags);
bool HvClearCurrentVmcsAndRecord();
__declspec(noreturn) void HvFailVmcsClear();
bool MarkCurrentVcpuLaunched();
void MarkCurrentVcpuRunning();
void MarkCurrentVcpuParked();
bool MarkCurrentVcpuTearingDown();
void MarkCurrentVcpuStopped();
ULONG HandleVmResumeFailure(GuestContext* context, u64 resume_flags);
__declspec(noreturn) void HvFatalBugCheck(GuestContext* context);
__declspec(noreturn) void HvHostExceptionBugCheck();
void VmExitHandler(GuestContext* context);

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
extern volatile LONG g_HvVmExitDebugHold;
extern volatile LONG g_HvLaunchFirstVmExitEntered;
extern volatile LONG g_HvLaunchDispatchReturned;
extern volatile LONG g_HvLaunchLastProbeProcessor;
extern volatile LONG g_HvLaunchLastDispatchProcessor;
extern volatile LONG g_HvLaunchLastPrepareProcessor;
extern volatile LONG g_HvLaunchLastReturnProcessor;

extern volatile u8 g_LinearAddressBits;
extern volatile u8 g_CetVmcsEnabled;
extern volatile u8 g_XsavesEnabled;
extern volatile u8 g_XstateMode;
extern volatile u64 g_XsavesMask;
extern volatile LONG g_HvVerboseLogging;
extern volatile u64 g_HvVmxOffFailureFlagsAsm;
}

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

enum VmxControlGeneration : u32 {
    VmxGenerationLegacy = 0,
    VmxGenerationTrue = 1,
    VmxGenerationTrueSecondary = 2,
    VmxGenerationTrueTertiary = 3,
};

enum FirstExitProbeState : long {
    FirstExitProbeIdle = 0,
    FirstExitProbeArmed = 1,
    FirstExitProbeVmExitEntered = 2,
    FirstExitProbeExitValidated = 3,
    FirstExitProbeReturned = 4,
    FirstExitProbeFailed = 5,
};

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

enum HvCrashBlobCaptureState : LONG {
    HvCrashBlobCaptureIdle = 0,
    HvCrashBlobCaptureWriting = 1,
    HvCrashBlobCaptureCommitted = 2,
};

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
    u64 VmcsClearFlags;
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


struct IntelCpuIdentity {
    u32 Family;
    u32 Model;
    u32 Stepping;
    u32 CoreType;
    IntelCpuBranch Branch;
    bool GenuineIntel;
};

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

static_assert(sizeof(HvIdtGate64) == 16, "IDT gate layout changed");

// Shared state. Definitions live in vmm_state.cpp.
extern VcpuContext* g_VcpuData;
extern u32 g_ProcessorCount;
extern volatile LONG g_HvLifecycle;
extern volatile LONG g_HvImagePinned;
extern "C" HvHostFaultRecord g_HvHostFaultRecord;
extern "C" volatile LONG64 g_HvRootNmiCount;
extern TargetCpuWork* g_HvTargetCpuWork;
extern TargetLaunchDpcWork* g_HvTargetLaunchDpcWork;
extern volatile LONG g_HvTargetWorkGeneration;
extern volatile LONG g_HvTargetActiveProcessor;
extern KBUGCHECK_REASON_CALLBACK_RECORD g_HvBugCheckReasonRecord;
extern bool g_HvBugCheckReasonRegistered;
extern HvCrashBlob* g_HvCrashBlob;
extern SIZE_T g_HvCrashBlobSize;
extern volatile LONG g_HvCrashBlobCaptured;
extern volatile LONG g_HvCrashBlobReleaseAuthorized;
extern HANDLE g_HvRuntimeWatchdogThread;
extern volatile LONG g_HvRuntimeWatchdogStop;
extern volatile LONG g_HvRuntimeWatchdogTicks;
extern volatile LONG g_HvRuntimeWatchdogBreakFired;
extern volatile LONG g_HvWaitpkgVmcsEnabled;
extern u64 g_VmxBasic;
extern u64 g_HostCr3;
extern bool g_VmxRequires32BitPhysicalAddress;
extern bool g_VmxFeatureContractInitialized;
extern bool g_VmxFeatureContractValid;
extern u64 g_EnumeratedXssMask;
extern u64 g_SupportedXssMask;
extern u64 g_GuestXssWriteMask;
extern u64 g_HostXssMask;
extern u64 g_HostXcr0Mask;
extern u64 g_DebugctlMask;
extern u32 g_XsaveStateSize;
extern u32 g_VmxCapabilityProfile;
extern volatile LONG g_VmxGuestOptionalProfile;
extern volatile LONG g_VmxGuestOptionalProfileCandidate;

inline constexpr LONG kHvLifecycleIdle = 0;
inline constexpr LONG kHvLifecycleStarting = 1;
inline constexpr LONG kHvLifecycleRunning = 2;
inline constexpr LONG kHvLifecycleStopping = 3;
inline constexpr LONG kHvLifecycleQuarantined = 4;

inline constexpr u32 kGuestOptionalProfileMask =
    VmxProfileRdtscp | VmxProfileInvpcid;
inline constexpr long kExitActionNone = 0;
inline constexpr long kExitActionResume = 1;
inline constexpr long kExitActionAbort = 2;
inline constexpr long kExitActionHalt = 3;
inline constexpr long kExitActionInject = 4;
inline constexpr u32 kFirstExitProbeLeaf = static_cast<u32>(HYPERVISOR_MAGIC);
inline constexpr u32 kFirstExitProbeEbx = 0xDEADC0DEU;
inline constexpr u32 kFirstExitProbeEcx = 0x00C0FFEEU;
inline constexpr u32 kFirstExitProbeEdx = 0x48564856U;
inline constexpr bool kEnableUserCpuidProbe = true;
inline constexpr u32 kUserProbeLeaf = static_cast<u32>(HYPERVISOR_MAGIC);
inline constexpr u32 kUserProbeSubleaf = 0x56455249U;
inline constexpr u32 kUserProbeSignatureEax = 0x48565031U;
inline constexpr u32 kUserProbeSignatureEdx = 0x564D5831U;
inline constexpr u64 kDebugctlArchitecturalMask =
    IA32_DEBUGCTL_ARCHITECTURAL_MASK;
inline constexpr u64 kCr0WriteProtect = 1ULL << 16;
inline constexpr bool kDebugSingleCpu = false;
inline constexpr u32 kDebugCpuIndex = 8;
inline constexpr bool kReserveCoordinatorCpu = true;
inline constexpr u32 kCoordinatorCpuIndex = 0;
inline constexpr SIZE_T kVmxHostStackSize = 0x8000;
inline constexpr u64 kVmxHostStackAlignment = 0x40;
inline constexpr bool kUseBroadcastLaunch = false;
inline constexpr bool kEnableLaunchFirstExitProbe = true;
inline constexpr LONGLONG kRuntimeWatchdogPoll100ns = 100000LL;
inline constexpr LONG kRuntimeWatchdogPrintEveryTicks = 50;
inline constexpr u64 kTargetOperationTimeout100ns = 50000000ULL;
inline constexpr LONGLONG kTargetCancelGrace100ns = 10000000LL;
inline constexpr u32 kStopRetryLimit = 32;
inline constexpr LONGLONG kStopRetryDelay100ns = -10000LL;
inline constexpr u32 TAG_HV00 = 0x30305648;
inline constexpr u32 TAG_HVST = 0x54535648;
inline constexpr u32 TAG_HVCB = 0x42435648;
inline constexpr u32 TAG_HVTR = 0x52545648;
inline constexpr u32 TAG_HVID = 0x44495648;
inline constexpr u64 kHvBuildId = static_cast<u64>(KNHV_BUILD_ID);
inline constexpr ULONG kHvFatalBugCheck = 0x48564D58UL;

// Cross-unit helpers. Functions that are truly local stay private to their
// implementation file; these declarations describe the stable internal ABI.
u32 CurrentProcessorIndex();
LONG CurrentProcessorTag();
u32 ControlMsr(u64 vmx_basic, u32 legacy_msr, u32 true_msr);
bool IsCanonical(u64 value);
bool ReadMsrSafe(u32 msr, u64* value);
bool WriteMsrSafe(u32 msr, u64 value);
u64 GetDebugctlCapabilityMask();
bool UpdateNativeTeardownContract(VcpuContext* vcpu);
bool ShouldLaunchOnThisProcessor(u32 id);
bool ShouldReportLaunchResult(u32 processor_index);
u32 ExpectedLaunchProcessorCount();
bool ShouldInjectFault(u32 cpu, u32 stage);
void WriteHvTrace(VcpuContext* vcpu, u32 cpu, HvTraceEvent event,
                  u64 arg0 = 0, u64 arg1 = 0, u64 arg2 = 0, u64 arg3 = 0);
bool ControlBitCanBeOne(u64 capability, u32 mask);
u32 BuildVmxCapabilityProfile(u64 vmx_basic, bool xsaves, bool cet_vmcs);
VmxControlGeneration SelectVmxControlGeneration(u32 profile);
IntelCpuIdentity QueryIntelCpuIdentity(u32 profile);
const char* IntelCpuBranchName(IntelCpuBranch branch);
bool IsIntelCpuBranchCompatible(const IntelCpuIdentity& identity, u32 profile);
bool ComputeXsaveAreaSize(u64 xcr0_mask, u64 xss_mask,
                          u64* enumerated_xss, u32* area_size);
bool ComputeStandardXsaveAreaSize(u64 xcr0_mask, u32* area_size);
bool VmxControlAllows(u32 msr, u32 mask);
bool EnsureFeatureControlForVmx();
bool IsIntelPtMsr(u32 msr);
bool IsCetStateMsr(u32 msr);
bool IsGdtSelectorUsable(u64 gdt_base, u16 gdt_limit, u16 selector,
                         bool allow_null, bool require_system,
                         bool require_code, bool require_kernel_privilege,
                         bool require_writable_data);
bool IsGuestTrSelectorUsable(u64 gdt_base, u16 gdt_limit, u16 selector);
bool VmxOk(u64 rflags);
bool IsVmEntryFailureQualificationDefined(u32 raw_reason);
void SetVmcsSetupPhase(VcpuContext* vcpu, VmcsSetupPhase phase);
long ReadVmcsFailureCommitState(const VcpuContext* vcpu);
u64 ReadVmcsFailureArg(const u64* value);
void ReadVmcsFailureRecord(const VcpuContext* vcpu, u32* commit_state,
                           u32* reason, u64* arg0, u64* arg1);
void PublishVmcsFailure(VcpuContext* vcpu, HvVmcsFailureReason reason,
                        u64 arg0 = 0,
                        u64 arg1 = 0);
bool VmWriteChecked(u64 field, u64 value);
bool VmReadChecked(u64 field, u64* value);
u64 ReadVmcsDiagnosticValidity(const VcpuContext* vcpu);
void SetVmcsDiagnosticValidity(VcpuContext* vcpu, u64 bits);
void ClearVmcsDiagnosticValidity(VcpuContext* vcpu, u64 bits);
bool VmcsValueMatches(VcpuContext* vcpu, u64 field, u64 actual,
                      u64 expected, u64 mask);
bool IsFixedCrValueValid(u64 value, u32 fixed0_msr, u32 fixed1_msr);
u64 GetCr4GuestHostMask();
bool IsSupervisorCetStateVmcsSafe(u64 supervisor_cet, u64 pl0_ssp,
                                  u64 pl1_ssp, u64 pl2_ssp,
                                  u64 interrupt_ssp_table);
bool PrepareVmxHostIdt(VcpuContext* vcpu, u64 native_idt_base,
                       u16 native_idt_limit, u32 cpu_id);
u64 PackSegmentSelectors(u16 first, u16 second, u16 third, u16 fourth);
bool IsValidPatValue(u64 value);
bool IsValidIa32eEfer(u64 value, u64 cr0);
bool IsValidDebugctl(u64 value);
bool IsValidCr3(u64 value, u64 cr4);
u64 NormalizeCr3(u64 value, u64 cr4);
u64 ReadLaunchCr3Field(const u64* field);
u64 PackLaunchCr3Metadata(u64 raw_guest_cr3, u64 raw_host_cr3,
                           u64 guest_cr4, u64 host_cr4);
bool IsValidArchitecturalCr3(u64 value, u64 cr4);
bool IsValidGuestDr7(u64 value);
bool IsValidGuestState(const GuestContext* context);
long ReadFirstExitProbeState(const VcpuContext* vcpu);
long AcquireFatalSnapshotCommitState(VcpuContext* vcpu);
u32 ReadNativeTeardownRejectMask(const VcpuContext* vcpu);
void FailFirstExitProbeIfActive(VcpuContext* vcpu, u32 cpu_id);
void InvalidateValidatedFirstExitProbe(VcpuContext* vcpu, u32 cpu_id);
void FailFirstExitProbeAtFatalBoundary(VcpuContext* vcpu, u32 cpu_id);
void MarkFirstExitProbeVmExitEntered(VcpuContext* vcpu, u32 cpu_id,
                                     u32 reason);
void CompleteFirstExitProbe(VcpuContext* vcpu, u32 cpu_id);
bool ArmFirstExitProbe(VcpuContext* vcpu, u32 cpu_id);
bool VerifyFirstExitProbeReturn(VcpuContext* vcpu, u32 cpu_id,
                                const int regs[4]);
bool RunFirstExitProbe(VcpuContext* vcpu, u32 cpu_id);
void RequestFatalStop(GuestContext* context);
void RequestAuthenticatedUnload(GuestContext* context, u32 exit_reason);
void ReleaseHvCrashBlob();
bool InitializeHvCrashBlob(u32 cpu_count);
void CaptureHvCrashBlob(ULONG_PTR bugcheck_code, ULONG_PTR bugcheck_arg1,
                        ULONG_PTR bugcheck_arg2, ULONG_PTR bugcheck_arg3,
                        ULONG_PTR bugcheck_arg4);
void StopHypervisorInternal(bool start_rollback);
void PinImageForParkedCpu();
bool HasUnresolvedTargetWork();
NTSTATUS QuarantineUnresolvedTargetWork();
bool LaunchResultNeedsDetail(u32 processor_index, const VcpuContext& vcpu);
void PrintLaunchResult(u32 processor_index, const VcpuContext& vcpu);
NTSTATUS StartRuntimeWatchdog(u32 target_cpu);
void StopRuntimeWatchdog();
NTSTATUS QueueTargetLaunchDpc(u32 processor_index);
NTSTATUS WaitTargetLaunchDpc(u32 processor_index, u64 deadline,
                             bool* unresolved);
NTSTATUS QueueTargetOperation(u32 processor_index, TargetOperation operation);
NTSTATUS WaitTargetOperation(u32 processor_index, u64 deadline,
                             bool* unresolved);
NTSTATUS StopTargetProcessorWithRetries(u32 processor_index, bool* unresolved);
NTSTATUS RunRuntimeCanary(u32 processor_index, const char* phase,
                          bool* unresolved);
bool BindCoordinatorToProcessor(u32 processor_index,
                                GROUP_AFFINITY* previous_affinity);
void ReleaseCoordinatorAffinity(GROUP_AFFINITY* previous_affinity, bool* bound);
bool IsTargetWorkTerminal(LONG state);
bool IsVcpuStopTerminal(long state);
bool HasParkedVcpu();
bool HasLiveVcpu();
bool HasUnresolvedVcpu();
bool HasUnclearedVmcs();

u32 AdjustControls(u32 ctl, u32 msr);
u64 AdjustCr0(u64 cr0);
u64 AdjustCr4(u64 cr4);
void* AllocContiguous(SIZE_T size, u64* physical_address);
bool HandleVmCall(GuestContext* context);
bool HandleMsrRead(GuestContext* context);
bool HandleMsrWrite(GuestContext* context);
void InjectGuestException(GuestContext* context, u8 vector, bool has_error_code,
                          u32 error_code = 0);
bool ConfigureMsrBitmap(VcpuContext* vcpu);
u32 ControlMandatoryOn(u32 msr);
void RecordLaunchBoundary(volatile LONG* counter,
                          volatile LONG* last_processor);
u64 GetGpr(const GuestContext* context, u8 reg);
bool SetGpr(GuestContext* context, u8 reg, u64 value);
bool HandleCrAccess(GuestContext* context);
bool HandleXsetbv(GuestContext* context, VcpuContext* vcpu);
u64 GetTssBase(u64 gdt_base, u16 gdt_limit, u16 selector);
bool SetupVmcs(const VcpuContext* vcpu, void* guest_sp, void* guest_ip);

extern "C" ULONG_PTR ProbeIpiRendezvousCallback(ULONG_PTR context);
extern "C" ULONG_PTR LaunchIpiDispatchCallback(ULONG_PTR context);
ULONG_PTR StopHvCallback(ULONG_PTR context);

extern "C" bool RegisterSecondaryDumpCallback();
extern "C" void UnregisterSecondaryDumpCallback();
bool IsVmxSupported();
extern "C" bool IsHypervisorQuarantined();
extern "C" void KeGenericCallDpc(PKDEFERRED_ROUTINE routine, PVOID context);
void LaunchBroadcastDpcRoutine(PKDPC dpc, PVOID deferred_context,
                               PVOID system_argument1,
                               PVOID system_argument2);

extern "C" NTSTATUS StartHypervisor();
extern "C" void StopHypervisor();
extern "C" bool IsHypervisorStopComplete();
extern "C" void QuarantineHypervisorImage();
