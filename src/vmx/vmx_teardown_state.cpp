// processor-local teardown state and lifecycle markers

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
u32 CurrentProcessorIndex() {
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

u64 PackSegmentSelectors(u16 first, u16 second,
                                               u16 third, u16 fourth) {
    return static_cast<u64>(first) |
           (static_cast<u64>(second) << 16) |
           (static_cast<u64>(third) << 32) |
           (static_cast<u64>(fourth) << 48);
}

bool IsNativeTeardownSegmentValid(
    u64 gdtBase, u16 gdtLimit, u64 selector, u64 limit, u64 ar,
    bool requireCode, bool requireWritableData) {
    if (selector > 0xFFFFULL || limit > 0xFFFFFFFFULL ||
        ar > 0xFFFFFFFFULL) {
        return false;
    }

    const u16 selector16 = static_cast<u16>(selector);
    if (selector16 == 0) {
        // A null SS is valid for a ring-0 64-bit IRET only when VMX marks it
        // unusable. CS never has a legal null form in this teardown path.
        return !requireCode && requireWritableData && limit == 0 &&
               ar == 0x10000ULL;
    }
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, selector16, false, false,
                             requireCode, true, requireWritableData)) {
        return false;
    }
    return HvGetSegmentLimit(selector16) == static_cast<u32>(limit) &&
           HvGetSegmentAr(selector16) == static_cast<u32>(ar);
}

// VMX restores the host descriptor tables on VM-exit. Native teardown can
// therefore use IRET only while the guest descriptor environment is unchanged.
// Windows may expose a transient null host SS while the guest has a valid
// kernel SS, so that selector is validated against the shared GDT instead of
// compared with the host snapshot.
bool UpdateNativeTeardownContract(VcpuContext* vcpu) {
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

    const bool guestSelectorsFit =
        guestCs <= 0xFFFFULL && guestSs <= 0xFFFFULL &&
        guestDs <= 0xFFFFULL && guestEs <= 0xFFFFULL &&
        guestFs <= 0xFFFFULL && guestGs <= 0xFFFFULL &&
        guestLdtr <= 0xFFFFULL && guestTr <= 0xFFFFULL;
    const u64 guestSelectorsLow =
        PackSegmentSelectors(static_cast<u16>(guestCs),
                             static_cast<u16>(guestSs),
                             static_cast<u16>(guestDs),
                             static_cast<u16>(guestEs));
    const u64 guestSelectorsHigh =
        PackSegmentSelectors(static_cast<u16>(guestFs), static_cast<u16>(guestGs),
                             static_cast<u16>(guestLdtr), static_cast<u16>(guestTr));
    const bool gdtSame = guestGdtBase == vcpu->HostGdtBase &&
                         guestGdtLimit == vcpu->HostGdtLimit;
    const bool guestSegmentsSafe =
        !gdtSame ||
        (IsNativeTeardownSegmentValid(
             vcpu->HostGdtBase, static_cast<u16>(vcpu->HostGdtLimit), guestCs,
             guestCsLimit, guestCsAr, true, false) &&
         IsNativeTeardownSegmentValid(
             vcpu->HostGdtBase, static_cast<u16>(vcpu->HostGdtLimit), guestSs,
             guestSsLimit, guestSsAr, false, true));
    constexpr u64 kSsSelectorMask = 0xFFFFULL << 16;
    const bool nonSsSelectorsSame =
        guestSelectorsFit &&
        (guestSelectorsLow & ~kSsSelectorMask) ==
            (vcpu->HostSegmentSelectorsLow & ~kSsSelectorMask) &&
        guestSelectorsHigh == vcpu->HostSegmentSelectorsHigh;
    const bool selectorsSame = nonSsSelectorsSame && guestSegmentsSafe;
    const bool csSsSame = guestCsLimit == vcpu->HostCsLimit &&
                          guestCsAr == vcpu->HostCsAr &&
                          guestSegmentsSafe;
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u launch marker saw unexpected stage=%ld "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u launch marker could not publish: "
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
