// crash snapshot and dump callback ownership

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;

static constexpr u64 kCrashBlobSignature = 0x48564342524D5541ULL;
static constexpr u32 kCrashBlobVersion = 14;
static const GUID kCrashBlobGuid = {
    0xC6A3D9F0, 0x2F6F, 0x4E4A,
    {0xA5, 0x9E, 0x61, 0x34, 0x12, 0x88, 0x4B, 0xE6}};
static constexpr const char kCrashBlobComponent[] = "KNHV_CrashBlob";

KBUGCHECK_REASON_CALLBACK_RECORD g_HvBugCheckReasonRecord{};
bool g_HvBugCheckReasonRegistered = false;
HvCrashBlob* g_HvCrashBlob = nullptr;
SIZE_T g_HvCrashBlobSize = 0;
volatile LONG g_HvCrashBlobCaptured = 0;
volatile LONG g_HvCrashBlobReleaseAuthorized = 0;
void ReleaseHvCrashBlob() {
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
bool InitializeHvCrashBlob(u32 cpuCount) {
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
        g_HvCrashBlob->Signature = kCrashBlobSignature;
        g_HvCrashBlob->Version = kCrashBlobVersion;
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
    g_HvCrashBlob->Signature = kCrashBlobSignature;
    g_HvCrashBlob->Version = kCrashBlobVersion;
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

void CaptureHvCrashBlob(ULONG_PTR bugcheckCode,
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
    blob->Signature = kCrashBlobSignature;
    blob->Version = kCrashBlobVersion;
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
        dumpData->Guid = kCrashBlobGuid;
        dumpData->OutBuffer = nullptr;
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    } else if (captureState != HvCrashBlobCaptureCommitted) {
        // A corrupted state must never be treated as a committed blob. Keep
        // the callback answer empty so dump code cannot copy stale memory.
        dumpData->Guid = kCrashBlobGuid;
        dumpData->OutBuffer = nullptr;
        dumpData->OutBufferLength = 0;
        dumpData->Flags = KB_SECONDARY_DATA_FLAG_NO_DEVICE_ACCESS;
        dumpData->Context = nullptr;
        return;
    }
    dumpData->Guid = kCrashBlobGuid;
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

extern "C" bool RegisterSecondaryDumpCallback() {
    if (g_HvBugCheckReasonRegistered) return true;

    const BOOLEAN ok = KeRegisterBugCheckReasonCallback(
        &g_HvBugCheckReasonRecord,
        HvSecondaryDumpDataCallback,
        KbCallbackSecondaryMultiPartDumpData,
        reinterpret_cast<PUCHAR>(const_cast<char*>(kCrashBlobComponent)));
    if (!ok) return false;

    g_HvBugCheckReasonRegistered = true;
    return true;
}

extern "C" void UnregisterSecondaryDumpCallback() {
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
