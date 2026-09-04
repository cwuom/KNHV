// VMCS construction and architectural state validation

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
// VMCS Setup

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
    KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMCS setup begin: vmxon_pa=0x%llX "
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
        KNHV_VERBOSE_PRINT(
            "[KNHV] CPU %u VMCS setup rejected CET without CR0.WP: "
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
        KNHV_VERBOSE_PRINT(
            "[KNHV] CPU %u VMCS setup rejected MSR state: valid=%u "
            "efer=0x%llX pat=0x%llX fs=0x%llX gs=0x%llX "
            "sysenter_cs=0x%llX sysenter_esp=0x%llX sysenter_eip=0x%llX\n",
            cpuId, msrSnapshotUsable ? 1U : 0U, hostEfer, pat, fsBase, gsBase,
            sysenterCs, sysenterEsp, sysenterEip);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureMsrSnapshot,
                           hostEfer, pat);
        return false;
    }
    // capture CET state once on the owning processor and reuse it for both
    // VMCS sides. This keeps the host and initial guest state coherent while
    // reuse the per-processor snapshot for both sides of the VMCS.
    u64 hostSCet = 0;
    u64 hostSsp = 0;
    u64 hostPl1Ssp = 0;
    u64 hostPl2Ssp = 0;
    u64 hostInterruptSspTable = 0;
    if (g_CetVmcsEnabled) {
        const bool cetSnapshotRead =
            ReadMsrSafe(MSR_IA32_S_CET, &hostSCet) &&
            ReadMsrSafe(MSR_IA32_PL0_SSP, &hostSsp) &&
            ReadMsrSafe(MSR_IA32_PL1_SSP, &hostPl1Ssp) &&
            ReadMsrSafe(MSR_IA32_PL2_SSP, &hostPl2Ssp) &&
            ReadMsrSafe(MSR_IA32_INTERRUPT_SSP_TABLE,
                        &hostInterruptSspTable);
        if (!cetSnapshotRead ||
            !IsSupervisorCetStateVmcsSafe(hostSCet, hostSsp, hostPl1Ssp,
                                          hostPl2Ssp,
                                          hostInterruptSspTable)) {
            WriteHvTrace(mutableVcpu, cpuId, HvTraceEventContractFail,
                         hostSCet, hostSsp, hostPl1Ssp,
                         hostInterruptSspTable);
            KNHV_VERBOSE_PRINT(
                "[KNHV] CPU %u VMCS setup rejected supervisor CET state: "
                "read=%u s_cet=0x%llX pl0=0x%llX pl1=0x%llX pl2=0x%llX "
                "ist=0x%llX\n",
                cpuId, cetSnapshotRead ? 1U : 0U, hostSCet, hostSsp,
                hostPl1Ssp, hostPl2Ssp, hostInterruptSspTable);
            PublishVmcsFailure(mutableVcpu, HvVmcsFailureControlPolicy,
                               hostSCet, hostSsp);
            return false;
        }
    }
    const u64 guestEfer = hostEfer;
    const u64 guestPat = pat;
    const bool guestTrUsable =
        IsGuestTrSelectorUsable(gdtBase, gdtLimit, trSelector);

    if (!guestTrUsable) {
        KNHV_VERBOSE_PRINT(
            "[KNHV] CPU %u VMCS setup rejected guest TR 0x%04X: "
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
    // usable SS, so set AR.Unusable for
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
        KNHV_VERBOSE_PRINT(
            "[KNHV] CPU %u VMCS descriptor preflight rejected: mask=0x%X "
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
        KNHV_VERBOSE_PRINT("[KNHV] VMCS setup rejected a non-empty LDTR 0x%04X\n",
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
        KNHV_VERBOSE_PRINT(
            "[KNHV] CPU %u VMCS setup rejected sampled guest TR: "
            "selector=0x%04X limit=0x%X ar=0x%X base=0x%llX\n",
            cpuId, trSelector, trLimit, trAr, tssBase);
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureSampledTr,
                           trLimit, trAr);
        return false;
    }

    if (!PrepareVmxHostIdt(mutableVcpu, idtBase, idtLimit, cpuId)) {
        WriteHvTrace(mutableVcpu, cpuId, HvTraceEventContractFail,
                     idtBase, idtLimit, mutableVcpu->VmxHostIdtBase, 0);
        KNHV_VERBOSE_PRINT(
            "[KNHV] CPU %u VMCS setup rejected private host IDT: "
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

    // Host State Configuration
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
    // by XSAVES. Keep the host and initial guest copies identical; later
    // guest WRMSR operations update the guest VMCS fields in the exit handler.
    if (g_CetVmcsEnabled) {
        if (!VmWriteChecked(HOST_S_CET, hostSCet) ||
            !VmWriteChecked(HOST_SSP, hostSsp) ||
            !VmWriteChecked(HOST_INTR_SSP_TABLE, hostInterruptSspTable)) {
            return false;
        }
    }

    WriteHvTrace(mutableVcpu, cpuId, HvTraceEventVmcsHostDone);
    if (ShouldInjectFault(cpuId, HvFaultAfterHostState)) {
        PublishVmcsFailure(mutableVcpu, HvVmcsFailureInjected,
                           HvFaultAfterHostState, 0);
        return false;
    }

    // Guest State Configuration
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

    const u64 guestSCet = hostSCet;
    const u64 guestSsp = hostSsp;
    const u64 guestInterruptSspTable = hostInterruptSspTable;
    if (g_CetVmcsEnabled) {
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMCS setup rejected guest entry pointers: "
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
    // restore the DPC's saved flags directly instead of inventing a
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
    KNHV_VERBOSE_PRINT("[KNHV] CPU %u guest launch flags: source=0x%llX "
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

    // VM Execution Controls
    SetVmcsSetupPhase(mutableVcpu, VmcsSetupPhaseExecutionControls);

    // initialize the baseline VMCS image. These fields are inactive in the
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
    // secondary enable control is unavailable. Enable the user-wait-and-pause
    // control only on the normal VMCS path.
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
            KNHV_VERBOSE_PRINT(
                "[KNHV] CPU %u WAITPKG VMCS contract rejected: "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMX primary controls require an "
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
    KNHV_VERBOSE_PRINT(
        "[KNHV] CPU %u secondary instruction contract: cpuid_waitpkg=%u "
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
            KNHV_VERBOSE_PRINT("[KNHV] CPU %u tertiary VMX controls write failed: "
                             "0x%llX\n", cpuId, tertiaryCtl);
            return false;
        }
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u tertiary VMX controls: 0x%llX\n",
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
    KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMCS setup %s: guest_cr3=0x%llX "
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
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMCS host: cr0=0x%llX cr3=0x%llX "
                         "cr4=0x%llX rip=0x%llX rsp=0x%llX cs=0x%llX "
                         "ss=0x%llX tr=0x%llX tr_base=0x%llX "
                         "gdt=0x%llX idt=0x%llX efer=0x%llX pat=0x%llX\n", cpuId,
                         vmcsHostCr0, vmcsHostCr3, vmcsHostCr4, vmcsHostRip,
                         vmcsHostRsp, vmcsHostCs, vmcsHostSs, vmcsHostTr,
                         vmcsHostTrBase, vmcsHostGdtBase, vmcsHostIdtBase,
                         vmcsHostEfer, vmcsHostPat);
        KNHV_VERBOSE_PRINT("[KNHV] CPU %u VMCS guest: cr0=0x%llX cr3=0x%llX "
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
