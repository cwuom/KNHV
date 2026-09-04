// processor operations, watchdog and teardown rendezvous

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
// Stop Logic

// this targeted callback must return ULONG_PTR
ULONG_PTR StopHvCallback(ULONG_PTR Context) {
    UNREFERENCED_PARAMETER(Context);

    if (!g_VcpuData) return 0;
    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return 0;
    VcpuContext* vcpu = &g_VcpuData[id];
    const long state = InterlockedCompareExchange(&vcpu->State, 0, 0);
    const long stage = InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0);
    KNHV_VERBOSE_PRINT("[KNHV] CPU %u stop callback: state=%ld vmexits=%ld\n", id, state,
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
            const u32 rejectMask = static_cast<u32>(
                InterlockedCompareExchange(&vcpu->NativeTeardownRejectMask,
                                           0, 0));
            const u64 entryInfo = vcpu->LastVmEntryIntrInfo;
            const u64 exitInfo = vcpu->LastVmExitIntrInfo;
            const u64 vectoringInfo = vcpu->LastIdtVectoringInfo;
            const u64 interruptibility = vcpu->LastGuestInterruptibility;
            const u64 pendingDebug = vcpu->LastGuestPendingDbgExceptions;

            // The VM-exit handler deliberately resumed the guest because this
            // stop attempt was not yet safe to convert into native execution.
            // Restore the launched ownership state so a later target worker can
            // retry the rendezvous on the same logical processor.
            InterlockedExchange(&vcpu->TeardownRequest, 0);
            MemoryBarrier();
            (void)InterlockedCompareExchange(&vcpu->LaunchStage,
                                              LaunchStageGuestActive,
                                              LaunchStageTeardown);
            (void)InterlockedCompareExchange(&vcpu->State, VcpuLaunched,
                                              VcpuTearingDown);
            MemoryBarrier();

            KNHV_VERBOSE_PRINT(
                "[KNHV] CPU %u stop deferred: reject=0x%08X "
                "intr=0x%llX entry=0x%llX exit=0x%llX vectoring=0x%llX "
                "pending_dbg=0x%llX\n",
                id, rejectMask, interruptibility, entryInfo, exitInfo,
                vectoringInfo, pendingDebug);
            return 0;
        }
        if (InterlockedCompareExchange(&vcpu->TeardownRequest, 0, 0) != 0) {
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u stop returned without teardown "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u stop callback exception; retaining VMX state "
                         "state=%ld stage=%ld vmexits=%ld\n", id,
                         InterlockedCompareExchange(&vcpu->State, 0, 0),
                         InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0),
                         vcpu->VmExitCount);
    }
    return 0;
}
// Native runtime watchdog

VOID RuntimeWatchdogThread(PVOID Context) {
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] native watchdog: tick=%ld cpu=%u state=%ld stage=%ld "
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
            KNHV_PASSIVE_PRINT(
                "[KNHV] native watchdog BREAK: cpu=%u vmx_abort=%u "
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

NTSTATUS StartRuntimeWatchdog(u32 targetCpu) {
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

void StopRuntimeWatchdog() {
    HANDLE threadHandle = g_HvRuntimeWatchdogThread;
    if (!threadHandle) return;

    InterlockedExchange(&g_HvRuntimeWatchdogStop, 1);
    (void)ZwWaitForSingleObject(threadHandle, FALSE, nullptr);
    ZwClose(threadHandle);
    g_HvRuntimeWatchdogThread = nullptr;
}

// Public API

void StopHypervisorInternal(bool startRollback);
void PinImageForParkedCpu();

bool IsTargetWorkTerminal(LONG state) {
    return state == TargetWorkSucceeded || state == TargetWorkFailed ||
           state == TargetWorkCancelled;
}

bool IsVcpuStopTerminal(long state) {
    return state == VcpuStopped || state == VcpuFailed ||
           state == VcpuUninitialized;
}

VOID TargetCpuWorker(PVOID Context) {
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

VOID TargetLaunchDpcRoutine(PKDPC Dpc,
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
        // keep the assembly entry as the direct DPC callee while this target DPC tracks completion
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

LARGE_INTEGER RemainingTargetTimeout(u64 deadline);

NTSTATUS QueueTargetLaunchDpc(u32 processorIndex) {
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

NTSTATUS WaitTargetLaunchDpc(u32 processorIndex,
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

NTSTATUS QueueTargetOperation(u32 processorIndex,
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

LARGE_INTEGER RemainingTargetTimeout(u64 deadline) {
    LARGE_INTEGER timeout{};
    const u64 now = KeQueryInterruptTime();
    if (now < deadline) {
        timeout.QuadPart = -static_cast<LONGLONG>(deadline - now);
    }
    return timeout;
}

NTSTATUS CloseCompletedTargetWork(TargetCpuWork* work) {
    const NTSTATUS result = work->Result;
    HANDLE threadHandle = work->ThreadHandle;
    work->ThreadHandle = nullptr;
    if (threadHandle) ZwClose(threadHandle);
    return result;
}

NTSTATUS WaitTargetOperation(u32 processorIndex,
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


NTSTATUS StopTargetProcessorWithRetries(u32 processorIndex,
                                                bool* unresolved) {
    if (!g_VcpuData || !unresolved || processorIndex >= g_ProcessorCount) {
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER retryDelay{};
    retryDelay.QuadPart = kStopRetryDelay100ns;

    for (u32 attempt = 1; attempt <= kStopRetryLimit; ++attempt) {
        const long state = InterlockedCompareExchange(
            &g_VcpuData[processorIndex].State, 0, 0);
        if (IsVcpuStopTerminal(state)) {
            return STATUS_SUCCESS;
        }
        if (state != VcpuLaunched && state != VcpuVmxOn) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        NTSTATUS status =
            QueueTargetOperation(processorIndex, TargetOperationStop);
        if (NT_SUCCESS(status)) {
            const u64 deadline =
                KeQueryInterruptTime() + kTargetOperationTimeout100ns;
            status = WaitTargetOperation(processorIndex, deadline, unresolved);
        }

        if (*unresolved || NT_SUCCESS(status)) {
            return status;
        }

        VcpuContext* vcpu = &g_VcpuData[processorIndex];
        const long retryState =
            InterlockedCompareExchange(&vcpu->State, 0, 0);
        const long retryStage =
            InterlockedCompareExchange(&vcpu->LaunchStage, 0, 0);
        const u32 rejectMask = static_cast<u32>(
            InterlockedCompareExchange(&vcpu->NativeTeardownRejectMask, 0, 0));

        KNHV_PASSIVE_PRINT(
            "[KNHV] CPU %u stop retry: attempt=%u/%u status=0x%08X "
            "state=%ld stage=%ld reject=0x%08X intr=0x%llX "
            "entry=0x%llX exit=0x%llX vectoring=0x%llX pending_dbg=0x%llX\n",
            processorIndex, attempt, kStopRetryLimit,
            static_cast<ULONG>(status), retryState, retryStage, rejectMask,
            vcpu->LastGuestInterruptibility, vcpu->LastVmEntryIntrInfo,
            vcpu->LastVmExitIntrInfo, vcpu->LastIdtVectoringInfo,
            vcpu->LastGuestPendingDbgExceptions);

        if (retryState != VcpuLaunched ||
            retryStage != LaunchStageGuestActive) {
            return status;
        }

        if (attempt != kStopRetryLimit) {
            (void)KeDelayExecutionThread(KernelMode, FALSE, &retryDelay);
        }
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS RunRuntimeCanary(u32 processorIndex,
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
    KNHV_PASSIVE_PRINT(
        "[KNHV] %s canary: cpu=%u status=0x%08X worker_state=%ld irql=%ld "
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

bool BindCoordinatorToProcessor(u32 processorIndex,
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
void ReleaseCoordinatorAffinity(GROUP_AFFINITY* previousAffinity,
                                        bool* bound) {
    if (!previousAffinity || !bound || !*bound) return;
    KeRevertToUserGroupAffinityThread(previousAffinity);
    *bound = false;
}

bool HasUnresolvedTargetWork() {
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

NTSTATUS QuarantineUnresolvedTargetWork() {
    PinImageForParkedCpu();
    InterlockedExchange(&g_HvLifecycle, kHvLifecycleQuarantined);
    return STATUS_SUCCESS;
}

bool LaunchResultNeedsDetail(u32 processorIndex,
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
                      (!kUseBroadcastLaunch &&
                       firstExitProbeState != FirstExitProbeReturned);
    }
    return needsDetail;
}

void PrintLaunchResult(u32 processorIndex, const VcpuContext& vcpu) {
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
        KNHV_PASSIVE_PRINT(
            "[KNHV] CPU %u launch result: state=%ld stage=%ld check=%ld "
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

    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u launch failure: state=%ld stage=%ld check=%ld "
        "vmexits=%ld launch_flags=0x%llX raw_reason=0x%08X basic=%u "
        "entry_failure=%u probe=%ld probe_exits=%ld probe_resumes=%ld "
        "probe_reason=%ld probe_action=%ld action=%ld resumes=%ld\n",
        processorIndex, state, stage, checkStage, vmExitCount,
        vcpu.LastLaunchFlags, vcpu.LastExitReasonRaw,
        vcpu.LastExitReasonBasic, vcpu.LastExitEntryFailure,
        firstExitProbeState, firstExitProbeExits, firstExitProbeResumes,
        probeReason, probeAction, action, vcpu.VmResumeAttempts);
    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u VMCS rejection: commit=%ld reason=%ld "
        "arg0=0x%llX arg1=0x%llX\n",
        processorIndex, vmcsFailureCommit, vmcsFailureReason,
        vmcsFailureArg0, vmcsFailureArg1);
    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u descriptor/xstate diag: reject_mask=0x%X "
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
    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u launch transition: msr=0x%08X msr_value=0x%llX "
        "rip=0x%llX rsp=0x%llX cr2=0x%llX exit_len=%llu "
        "qualification=0x%llX instrerr=0x%llX "
        "resume_flags=0x%llX probe_flags=0x%llX\n",
        processorIndex, vcpu.LastExitMsrIndex, vcpu.LastExitMsrValue,
        vcpu.LastGuestRip, vcpu.LastGuestRsp, vcpu.LastGuestCr2,
        vcpu.LastExitInstructionLength, vcpu.LastExitQualification,
        vcpu.LastVmInstructionError, vcpu.LastVmResumeFlags,
        probeResumeFlags);
    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u VMCS access: setup_phase=%ld vmwrite_failed=%ld "
        "write_field=0x%llX write_flags=0x%llX write_error=0x%llX "
        "vmread_failed=%ld read_field=0x%llX read_flags=0x%llX "
        "read_error=0x%llX\n",
        processorIndex, vmcsSetupPhase, vmcsWriteFailed,
        vcpu.FirstVmcsWriteField, vcpu.FirstVmcsWriteFlags,
        vcpu.FirstVmcsWriteError, vmcsReadFailed, vcpu.FirstVmcsReadField,
        vcpu.FirstVmcsReadFlags, vcpu.FirstVmcsReadError);
    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u VMCS image: mismatch=%ld field=0x%llX "
        "expected=0x%llX actual=0x%llX mask=0x%llX validity=0x%llX "
        "vmclear=0x%llX current=%ld vmptrld=0x%llX\n",
        processorIndex, vmcsValueMismatch, vcpu.FirstVmcsMismatchField,
        vcpu.FirstVmcsMismatchExpected, vcpu.FirstVmcsMismatchActual,
        vcpu.FirstVmcsMismatchMask, diagnosticValidity,
        vcpu.LastVmclearFlags, vmcsCurrent, vcpu.LastVmptrldFlags);
    KNHV_PASSIVE_PRINT(
        "[KNHV] CPU %u VMCS capabilities: primary=0x%llX tertiary=0x%llX "
        "cr3_raw_guest=0x%llX cr3_guest=0x%llX "
        "cr3_raw_host=0x%llX cr3_host=0x%llX cr3_meta=0x%llX\n",
        processorIndex, vcpu.PrimaryControlsCapability,
        vcpu.TertiaryControlsAllowed, launchRawGuestCr3, launchGuestCr3,
        launchRawHostCr3, launchHostCr3, launchCr3Metadata);
}
