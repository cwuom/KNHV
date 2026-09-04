// VMX launch orchestration and per-CPU preparation

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
// Launch Logic


// these symbols form a debugger-readable recorder for the launch rendezvous
// producers only use atomic memory operations because they run at IPI_LEVEL
extern "C" {
// these broadcast helpers are exported by ntoskrnl but are omitted from the
// current WDK headers. They provide the rendezvous barrier for startup and teardown

extern void KeSignalCallDpcSynchronize(PVOID SystemArgument2);
extern void KeSignalCallDpcDone(PVOID SystemArgument1);
}
LONG CurrentProcessorTag() {
    PROCESSOR_NUMBER number = {};
    KeGetCurrentProcessorNumberEx(&number);
    return static_cast<LONG>((static_cast<ULONG>(number.Group) << 16) |
                             static_cast<ULONG>(number.Number));
}

void RecordLaunchBoundary(volatile LONG* counter,
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

// enter VMX from the generic DPC itself. Keeping the assembly
// save/restore pair as the direct DPC callee makes the guest return address
// the DPC continuation, without an additional C++ dispatch frame.
VOID LaunchBroadcastDpcRoutine(PKDPC Dpc,
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
        KNHV_VERBOSE_PRINT("[KNHV] generic DPC returned before GuestActive: "
                         "cpu=%u stage=%ld\n", genericCpu, genericStage);
    }

    // KeGenericCallDpc owns the rendezvous lifetime. Signal only after the
    // VMX transition has returned to this DPC, so the callback cannot signal
    // completion while the processor is still in VMX root
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

    KNHV_VERBOSE_PRINT("[KNHV] CPU %u prepare begin: guest_sp=0x%llX guest_ip=0x%llX "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u rejected: vendor is not GenuineIntel\n",
                             id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u64 localVmxBasic = 0;
        if (!ReadMsrSafe(MSR_IA32_VMX_BASIC, &localVmxBasic)) {
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u rejected: VMX_BASIC read failed\n",
                             id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const u32 localProfile = BuildVmxCapabilityProfile(
            localVmxBasic, g_XsavesEnabled != 0, g_CetVmcsEnabled != 0);
        const IntelCpuIdentity identity = QueryIntelCpuIdentity(localProfile);
        if (!IsIntelCpuBranchCompatible(identity, localProfile)) {
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u rejected: family=%u model=0x%X "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u DEBUGCTL capability mismatch: "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u has active unsupported FRED: "
                             "cr4=0x%llX\n", id, localCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (g_XstateMode == XstateSaveFxsave &&
            (!localFxsrEnumerated || (localCr4 & CR4_OSFXSR) == 0 ||
             (localCr4 & CR4_OSXSAVE) != 0 ||
             (localCr4 & CR4_PKE) != 0 ||
             (localCr4 & CR4_FRED) != 0)) {
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u lacks the FXSAVE state contract: "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u original CR0/CR4 violates VMX fixed "
                             "bits: cr0=0x%llX cr4=0x%llX\n", id, localCr0,
                             localCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const bool localCet = (localCr4 & CR4_CET) != 0;
        if (localCet != (g_CetVmcsEnabled != 0)) {
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u local CR4.CET contract mismatch: "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u local XCR0/XSAVE contract mismatch: "
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
                KNHV_VERBOSE_PRINT("[KNHV] CPU %u active XFD state changed during "
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
                    KNHV_VERBOSE_PRINT("[KNHV] CPU %u has active unsupported FRED\n", id);
                    InterlockedExchange(&vcpu->State, VcpuFailed);
                    return 0;
                }
            }
        }
        if (localWaitpkgEnumerated &&
            !VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                              SECONDARY_ENABLE_USER_WAIT_PAUSE)) {
            KNHV_VERBOSE_PRINT(
                "[KNHV] CPU %u WAITPKG contract rejected: CPUID.7.0.ECX[5]=1 "
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
                KNHV_VERBOSE_PRINT("[KNHV] CPU %u has active unsupported U_CET: "
                                 "value=0x%llX\n", id, localUCet);
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            if (localCetShadowStackEnumerated) {
                u64 localPl3Ssp = 0;
                if (!ReadMsrSafe(MSR_IA32_PL3_SSP, &localPl3Ssp) ||
                    localPl3Ssp != 0) {
                    KNHV_VERBOSE_PRINT("[KNHV] CPU %u has active unsupported "
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
                KNHV_VERBOSE_PRINT("[KNHV] CPU %u local XSAVES layout mismatch: "
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
            const bool localCetStateRead =
                ReadMsrSafe(MSR_IA32_S_CET, &localSCet) &&
                ReadMsrSafe(MSR_IA32_PL0_SSP, &localPl0) &&
                ReadMsrSafe(MSR_IA32_PL1_SSP, &localPl1) &&
                ReadMsrSafe(MSR_IA32_PL2_SSP, &localPl2) &&
                ReadMsrSafe(MSR_IA32_INTERRUPT_SSP_TABLE, &localIst);
            if (!localCetStateRead ||
                !IsSupervisorCetStateVmcsSafe(localSCet, localPl0, localPl1,
                                               localPl2, localIst)) {
                WriteHvTrace(vcpu, id, HvTraceEventContractFail, localSCet,
                             localPl0, localPl1, localIst);
                KNHV_VERBOSE_PRINT(
                    "[KNHV] CPU %u supervisor CET state outside VMCS contract: "
                    "s_cet=0x%llX pl0=0x%llX pl1=0x%llX pl2=0x%llX "
                    "ist=0x%llX read=%u\n",
                    id, localSCet, localPl0, localPl1, localPl2, localIst,
                    localCetStateRead ? 1U : 0U);
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u local contract: CR4=0x%llX XSAVES=%u "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMX state profile mismatch: "
                             "local=0x%X expected=0x%X required=0x%X\n", id,
                             vcpu->VmxProfile, g_VmxCapabilityProfile,
                             globalProfileMask);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localCr4 & CR4_PKE) != 0 &&
            (localXcr0 & XCR0_PKRU) == 0) {
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u has CR4.PKE without PKRU XSTATE: "
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
            KNHV_VERBOSE_PRINT("[KNHV] Processor %u requires 32-bit VMX physical addresses\n", id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((vcpu->HostStackTop & 0x3FULL) != 0 ||
            ((vcpu->HostStackTop - VMEXIT_FRAME_SIZE) & 0x3FULL) != 0) {
            KNHV_VERBOSE_PRINT("[KNHV] Processor %u has an unaligned VM-exit XSAVE frame\n", id);
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u host DR7 has reserved bits: "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u host DEBUGCTL has unsupported bits: "
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
        // KERNEL_GS shadow. They are read by the VM-exit entry before any C++ code is
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMXON failed: flags=0x%llX cr0=0x%llX "
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
                KNHV_VERBOSE_PRINT("[KNHV] CPU %u IA32_XSS transition rejected: "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMCS ready; entering VMLAUNCH: revision=0x%X "
                         "vmcs_pa=0x%llX host_rsp=0x%llX\n", id, vcpu->RevisionId,
                         vcpu->VmcsPhys, vcpu->HostStackTop);
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&vcpu->LaunchCheckStage, LaunchCheckException);
        PublishVmcsFailure(vcpu, HvVmcsFailureException,
                           static_cast<u64>(LaunchCheckException), 0);
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u prepare raised an exception: vmx_active=%u "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u launch rollback lost stage ownership: "
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
    KNHV_VERBOSE_PRINT("[KNHV] VMLAUNCH rollback on processor %u flags 0x%llX "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u launch rollback lost VMX ownership: "
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
