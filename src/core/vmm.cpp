// public start and stop lifecycle

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
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
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected by the VMX capability gate\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    // a late-launch guest begins with interrupted Windows XSTATE, so each live
    // supervisor component must fit in the fixed preservation frame
    if (g_XsavesEnabled &&
        ((g_HostXssMask & ~g_XsavesMask) != 0 ||
         g_XsaveStateSize == 0 ||
         g_XsaveStateSize > VMEXIT_XSAVE_MAX ||
         g_XsaveStateSize > sizeof(GuestContext{}.FxArea))) {
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected: unsupported live XSS "
                 "host=0x%llX preserve=0x%llX frame=%lu\n",
                 g_HostXssMask, g_XsavesMask,
                 static_cast<ULONG>(g_XsaveStateSize));
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor: profile=0x%X CET_VMCS=%u XSAVES=%u\n",
             g_VmxCapabilityProfile, g_CetVmcsEnabled ? 1U : 0U,
             g_XsavesEnabled ? 1U : 0U);
    KNHV_PASSIVE_PRINT("[KNHV] late-launch baseline: cpuid=native "
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
            KNHV_PASSIVE_PRINT("[KNHV] FXSAVE contract has an invalid frame size: %lu\n",
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
            KNHV_PASSIVE_PRINT("[KNHV] XSAVES area too large: need %lu bytes, have %lu\n",
                     static_cast<ULONG>(xsaveSize),
                     static_cast<ULONG>(sizeof(GuestContext{}.FxArea)));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    } else {
        __cpuidex(regs, 0xD, 0);
        u32 xsaveSize = static_cast<u32>(regs[1]);
        if (xsaveSize > VMEXIT_XSAVE_MAX ||
            xsaveSize > sizeof(GuestContext{}.FxArea)) {
            KNHV_PASSIVE_PRINT("[KNHV] XSAVE area too large: need %lu bytes, have %lu\n",
                     static_cast<ULONG>(xsaveSize),
                     static_cast<ULONG>(sizeof(GuestContext{}.FxArea)));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    }

    __try {
        g_VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected: IA32_VMX_BASIC read faulted\n");
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
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected: VMX_BASIC=0x%llX regionSize=0x%llX\n",
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
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected: system CR3 is invalid (0x%llX)\n",
                 g_HostCr3);
        return rejectStart(STATUS_NOT_SUPPORTED);
    }

    RtlZeroMemory(&g_HvHostFaultRecord, sizeof(g_HvHostFaultRecord));

    g_ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (g_ProcessorCount == 0) {
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected: no active processors\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    if (!InitializeHvCrashBlob(g_ProcessorCount)) {
        KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor rejected: failed to initialize crash blob\n");
        return rejectStart(STATUS_INSUFFICIENT_RESOURCES);
    }
    KNHV_PASSIVE_PRINT("[KNHV] StartHypervisor: processors=%u host_cr3=0x%llX "
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
                KNHV_PASSIVE_PRINT("[KNHV] CPU %u allocation failed: vmxon=%u vmcs=%u "
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
    KNHV_PASSIVE_PRINT("[KNHV] allocations complete: processors=%u\n", g_ProcessorCount);

    // VMXON, the live Windows snapshot, guest XSS installation, and VMLAUNCH
    // remain in one callback per CPU. The save frame stays owned by the
    // interrupted DPC throughout staged startup.
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

        KNHV_PASSIVE_PRINT(
            "[KNHV] DEBUG single-CPU self-test: launching CPU %u only\n",
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] DEBUG single-CPU launch became unresolved\n");
            const NTSTATUS quarantineStatus = QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }

        const long debugState = InterlockedCompareExchange(
            &g_VcpuData[debugCpu].State, 0, 0);
        const long debugStage = InterlockedCompareExchange(
            &g_VcpuData[debugCpu].LaunchStage, 0, 0);

        KNHV_PASSIVE_PRINT(
            "[KNHV] DEBUG single-CPU result: cpu=%u status=0x%08X "
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

            KNHV_PASSIVE_PRINT(
                "[KNHV] DEBUG single-CPU VMLAUNCH path failed; rolling back\n");
            PrintLaunchResult(debugCpu, g_VcpuData[debugCpu]);

            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return STATUS_NOT_SUPPORTED;
        }

        // the launch DPC and its private CPUID probe have returned. run a
        // second CPUID from a normal system thread that is scheduled onto CPU1.
        // this is the first test that crosses the boundary from the launch DPC
        // back to a scheduler context and then through a normal VM-exit.
        KNHV_PASSIVE_PRINT(
            "[KNHV] DEBUG single-CPU launch returned; "
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
        KNHV_PASSIVE_PRINT(
            "[KNHV] DEBUG post-DPC canary: cpu=%u status=0x%08X "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] DEBUG post-DPC canary became unresolved; "
                "quarantining VMX image\n");
            const NTSTATUS quarantineStatus =
                QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }

        if (!NT_SUCCESS(targetStatus)) {
            KNHV_PASSIVE_PRINT(
                "[KNHV] DEBUG post-DPC canary failed; retaining detailed "
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

        KNHV_PASSIVE_PRINT(
            "[KNHV] DEBUG single-CPU runtime contract passed: cpu=%u "
            "vmexits=%ld resumes=%ld waitpkg_ctl=%ld\n",
            debugCpu,
            InterlockedCompareExchange(
                &g_VcpuData[debugCpu].VmExitCount, 0, 0),
            InterlockedCompareExchange(
                &g_VcpuData[debugCpu].VmResumeAttempts, 0, 0),
            InterlockedCompareExchange(&g_HvWaitpkgVmcsEnabled, 0, 0));

        const NTSTATUS watchdogStatus = StartRuntimeWatchdog(debugCpu);
        KNHV_PASSIVE_PRINT(
            "[KNHV] native watchdog start: target_cpu=%u observer_cpu=%u "
            "status=0x%08X poll_ms=10 print_ms=500 "
            "break_on=vmx_abort/xss_reject/vmresume/fatal/hostfault/triple\n",
            debugCpu, kCoordinatorCpuIndex,
            static_cast<ULONG>(watchdogStatus));

        ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                    &coordinatorBound);
        return STATUS_SUCCESS;
    }

    KNHV_PASSIVE_PRINT(
        "[KNHV] ALLCPU staged bring-up: processors=%u coordinator=%u "
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

    if constexpr (kUseBroadcastLaunch) {
        // the broadcast path keeps the assembly entry as the direct DPC callee,
        // but it cannot impose a timeout while a CPU is inside VM-entry
        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        KNHV_PASSIVE_PRINT(
            "[KNHV] launching all processors through KeGenericCallDpc\n");
        KeGenericCallDpc(LaunchBroadcastDpcRoutine, nullptr);

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
            KNHV_VERBOSE_PRINT(
                "[KNHV] CPU %u generic DPC launch result: state=%ld stage=%ld "
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
        KNHV_PASSIVE_PRINT(
            "[KNHV] generic DPC launch completed: %u/%u processors\n",
            launchedCount, expected);
    } else {
        // launch one processor at a time to keep the coordinator alive, give
        // every target a finite completion deadline, and preserve per-CPU
        // failure state when VM-entry or VM-exit cannot return
        KNHV_PASSIVE_PRINT(
            "[KNHV] launching processors through staged target DPCs: "
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
                KNHV_PASSIVE_PRINT(
                    "[KNHV] CPU %u staged launch: status=0x%08X state=%ld "
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
                KNHV_PASSIVE_PRINT(
                    "[KNHV] CPU %u staged CR3: raw_guest=0x%llX guest=0x%llX "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] staged non-coordinator launch completed: "
                "%u/%u processors first_exit=%u/%u total_vmexits=%llu "
                "vmexit_asm=%ld first_vmexit=%ld\n",
                launchedCount, stagedExpected,
                firstExitReturned, stagedExpected, totalVmExits,
                InterlockedCompareExchange(&g_HvLaunchVmExitAsmReached, 0, 0),
                InterlockedCompareExchange(&g_HvLaunchFirstVmExitEntered, 0, 0));
        } else {
            KNHV_PASSIVE_PRINT(
                "[KNHV] staged launch stopped: status=0x%08X launched=%u/%u "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] all-core handoff failed: no verified VMX CPU available\n");
            StopHypervisorInternal(true);
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return STATUS_NOT_SUPPORTED;
        }

        ReleaseCoordinatorAffinity(&coordinatorAffinity, &coordinatorBound);
        if (!BindCoordinatorToProcessor(handoffProcessor,
                                        &coordinatorAffinity)) {
            KNHV_PASSIVE_PRINT(
                "[KNHV] all-core handoff failed: cannot bind startup thread "
                "to verified CPU %u\n",
                handoffProcessor);
            StopHypervisorInternal(true);
            return STATUS_INVALID_DEVICE_STATE;
        }
        coordinatorBound = true;

        KNHV_PASSIVE_PRINT(
            "[KNHV] all-core handoff: startup thread moved to verified CPU %u; "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] coordinator CPU %u launch became unresolved; "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] coordinator CPU %u launch failed: "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] coordinator CPU %u runtime canary became unresolved; "
                "quarantining VMX image\n",
                reservedProcessor);
            const NTSTATUS quarantineStatus =
                QuarantineUnresolvedTargetWork();
            ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                        &coordinatorBound);
            return quarantineStatus;
        }
        if (!NT_SUCCESS(targetStatus)) {
            KNHV_PASSIVE_PRINT(
                "[KNHV] coordinator CPU %u runtime canary failed\n",
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
        KNHV_PASSIVE_PRINT(
            "[KNHV] all %u processors launched; running final per-CPU "
            "runtime canary sweep\n",
            expected);

        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            targetStatus =
                RunRuntimeCanary(i, "all-core final", &unresolved);
            if (unresolved) {
                KNHV_PASSIVE_PRINT(
                    "[KNHV] final canary sweep became unresolved on CPU %u; "
                    "quarantining VMX image\n",
                    i);
                const NTSTATUS quarantineStatus =
                    QuarantineUnresolvedTargetWork();
                ReleaseCoordinatorAffinity(&coordinatorAffinity,
                                            &coordinatorBound);
                return quarantineStatus;
            }
            if (!NT_SUCCESS(targetStatus)) {
                KNHV_PASSIVE_PRINT(
                    "[KNHV] final canary sweep failed on CPU %u: "
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

        KNHV_PASSIVE_PRINT(
            "[KNHV] all-core runtime contract passed: launched=%u/%u "
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
        KNHV_VERBOSE_PRINT("[KNHV] StartHypervisor rejected: only %u/%u expected processors entered VMX\n",
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

bool HasParkedVcpu() {
    if (!g_VcpuData) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        const long state =
            InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
        if (state == VcpuParked) return true;
    }
    return false;
}

bool HasLiveVcpu() {
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
bool HasUnresolvedVcpu() {
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
bool HasUnclearedVmcs() {
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
void PinImageForParkedCpu() {
    if (!g_HvDriverObject ||
        InterlockedCompareExchange(&g_HvImagePinned, 1, 0) != 0) {
        return;
    }
    ObReferenceObject(g_HvDriverObject);
    KNHV_VERBOSE_PRINT("[KNHV] parked CPU quarantined; driver image pinned\n");
}

void StopHypervisorInternal(bool startRollback) {
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
        // Stop one logical processor at a time. Each successful VMXOFF creates
        // another native processor before the next rendezvous begins, while a
        // transient teardown rejection is resumed and retried instead of
        // parking many processors concurrently.
        for (u32 i = 0; i < g_ProcessorCount; ++i) {
            if (i == reservedProcessor) continue;
            const long state =
                InterlockedCompareExchange(&g_VcpuData[i].State, 0, 0);
            if (state != VcpuLaunched && state != VcpuVmxOn) continue;

            const NTSTATUS status =
                StopTargetProcessorWithRetries(i, &unresolved);
            if (!NT_SUCCESS(status)) {
                stopFailed = true;
                break;
            }
        }
        KeRevertToUserGroupAffinityThread(&coordinatorAffinity);
        coordinatorBound = false;
    }

    const long reservedState = InterlockedCompareExchange(
        &g_VcpuData[reservedProcessor].State, 0, 0);
    if (!unresolved && !stopFailed &&
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
            const NTSTATUS status =
                StopTargetProcessorWithRetries(reservedProcessor, &unresolved);
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
