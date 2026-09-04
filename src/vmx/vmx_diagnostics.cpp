// VMCS diagnostics and first-exit proof helpers

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
bool VmxOk(u64 rflags) {
    return ((rflags & 1ULL) == 0) && ((rflags & (1ULL << 6)) == 0);
}
// Intel defines exit qualification for ordinary exits and for entry-failure
// reasons 33 and 34 only.  Reason 41 and any future entry-failure reason leave
// this VMCS field unmodified, so it must not be published as current evidence
bool IsVmEntryFailureQualificationDefined(
    u32 rawReason) {
    if ((rawReason & 0x80000000U) == 0) return true;
    const u32 basicReason = rawReason & 0xFFFFU;
    return basicReason == VM_EXIT_REASON_INVALID_GUEST_STATE ||
           basicReason == VM_EXIT_REASON_MSR_LOADING;
}

void SetVmcsSetupPhase(VcpuContext* vcpu,
                                             VmcsSetupPhase phase) {
    if (vcpu) {
        InterlockedExchange(&vcpu->VmcsSetupPhase, phase);
    }
}

long ReadVmcsFailureCommitState(
    const VcpuContext* vcpu) {
    if (!vcpu) return HvVmcsFailureEmpty;
    return InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->VmcsFailureCommitState), 0, 0);
}

u64 ReadVmcsFailureArg(const u64* value) {
    if (!value) return 0;
    return static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(const_cast<u64*>(value)), 0, 0));
}

// copy the first-wins record only when its commit word stays stable. A crash
// callback may run while a VMX-root callback is publishing the two arguments
// and must never expose a half-written tuple
void ReadVmcsFailureRecord(const VcpuContext* vcpu,
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

void PublishVmcsFailure(VcpuContext* vcpu,
                               HvVmcsFailureReason reason,
                               u64 arg0,
                               u64 arg1) {
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

bool VmWriteChecked(u64 field, u64 value) {
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

bool VmReadChecked(u64 field, u64* value) {
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

u64 ReadVmcsDiagnosticValidity(
    const VcpuContext* vcpu) {
    if (!vcpu) return HvVmcsValidityNone;
    return static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(
            const_cast<u64*>(&vcpu->VmcsDiagnosticValidity)),
        0, 0));
}

void SetVmcsDiagnosticValidity(VcpuContext* vcpu,
                                                    u64 bits) {
    if (!vcpu || bits == HvVmcsValidityNone) return;
    InterlockedOr64(reinterpret_cast<volatile LONG64*>(
                        &vcpu->VmcsDiagnosticValidity),
                    static_cast<LONG64>(bits));
}

void ClearVmcsDiagnosticValidity(VcpuContext* vcpu,
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

bool VmcsValueMatches(VcpuContext* vcpu, u64 field,
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

bool IsFixedCrValueValid(u64 value, u32 fixed0Msr,
                                               u32 fixed1Msr) {
    u64 fixed0 = 0;
    u64 fixed1 = 0;
    return ReadMsrSafe(fixed0Msr, &fixed0) && ReadMsrSafe(fixed1Msr, &fixed1) &&
           (value & fixed0) == fixed0 && (value & ~fixed1) == 0;
}

u64 GetCr4GuestHostMask() {
    // A live Windows kernel has already committed its CR4 contract before
    // this driver loads. Keeping both guest and host masks at zero avoids
    // trapping ordinary CR4 updates or synthesizing a view
    // that differs from the native coordinator processor.
    return 0;
}

bool IsCanonical(u64 value) {
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

bool IsSupervisorCetStateVmcsSafe(
    u64 supervisorCet, u64 pl0Ssp, u64 pl1Ssp, u64 pl2Ssp,
    u64 interruptSspTable) {
    // vmx checks the CET fields even when the enable bits are clear. keep the
    // same reserved-bit, bitmap, SSP, and interrupt-table rules as VM-entry
    constexpr u64 kCetReservedBits = 0xFULL << 6;
    constexpr u64 kCetSuppress = 1ULL << 10;
    constexpr u64 kCetTracker = 1ULL << 11;
    constexpr u64 kCetBitmapBaseAlignmentBits = 0x3ULL << 12;
    constexpr u64 kSspReservedBits = 0x3ULL;

    if ((supervisorCet & IA32_CET_ENABLE_MASK) != 0 ||
        (supervisorCet & kCetReservedBits) != 0 ||
        (supervisorCet & kCetBitmapBaseAlignmentBits) != 0 ||
        !IsCanonical(supervisorCet) ||
        ((supervisorCet & kCetSuppress) != 0 &&
         (supervisorCet & kCetTracker) != 0)) {
        return false;
    }
    if (!IsCanonical(pl0Ssp) || (pl0Ssp & kSspReservedBits) != 0) {
        return false;
    }
    // pl1/pl2 have no vmcs fields in this monitor. keep rejecting a live
    // value rather than silently exposing an unpreserved supervisor state
    if (pl1Ssp != 0 || pl2Ssp != 0) return false;
    return IsCanonical(interruptSspTable);
}

void SetVmxHostIdtHandler(HvIdtGate64* gate,
                                                void (*handler)()) {
    if (!gate || !handler) return;
    const u64 address = reinterpret_cast<u64>(handler);
    gate->OffsetLow = static_cast<u16>(address & 0xFFFFULL);
    gate->OffsetMiddle = static_cast<u16>((address >> 16) & 0xFFFFULL);
    gate->OffsetHigh = static_cast<u32>(address >> 32);

    // use a private host-IDT without dedicated IST stacks. A uniform no-IST
    // frame also lets the raw assembly
    // recorder compute the interrupted RSP without guessing Windows' per-vector
    // IST policy.
    gate->Ist = 0;
}

bool PrepareVmxHostIdt(VcpuContext* vcpu, u64 nativeIdtBase,
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
    // a VMX-root NMI must not fall straight into the Windows NMI entry path.
    // Consume only NMIs that arrive
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

bool IsValidPatValue(u64 value) {
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

bool IsValidIa32eEfer(u64 value, u64 cr0) {
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

bool IsValidDebugctl(u64 value) {
    return (value & ~g_DebugctlMask) == 0;
}

u64 GetDebugctlCapabilityMask() {
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

bool IsValidCr3(u64 value, u64 cr4 = __readcr4()) {
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

u64 NormalizeCr3(u64 value, u64 cr4) {
    // CR3[63] is a MOV-to-CR3 no-flush hint, not persistent architectural
    // state.  VMCS guest CR3 validation requires the reserved bit to be clear.
    return (cr4 & CR4_PCIDE) != 0 ? value & ~(1ULL << 63) : value;
}

u64 ReadLaunchCr3Field(const u64* field) {
    // A timed-out launch DPC can still publish this diagnostic while the
    // passive coordinator is reading it. Use an atomic 64-bit load so a
    // debugger sees one complete value instead of a torn pair of DWORDs.
    if (!field) return 0;
    return static_cast<u64>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(const_cast<u64*>(field)), 0, 0));
}

u64 PackLaunchCr3Metadata(u64 rawGuestCr3,
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

bool IsValidArchitecturalCr3(u64 value, u64 cr4) {
    // The no-flush bit belongs only to a MOV-to-CR3 operand. It must never
    // survive in the architectural guest CR3 or in a teardown snapshot.
    return (value & (1ULL << 63)) == 0 && IsValidCr3(value, cr4);
}

bool IsValidGuestDr7(u64 value) {
    // DR7 is a 32-bit architectural register. Bit 10 is fixed to one and
    // bits 11 and 12 are reserved; rejecting them before native teardown
    // avoids a debug exception while the guest frame is being restored.
    constexpr u64 kDr7Reserved = (1ULL << 11) | (1ULL << 12) |
                                 (1ULL << 14) | (1ULL << 15);
    return (value & ~0xFFFFFFFFULL) == 0 &&
           (value & (1ULL << 10)) != 0 && (value & kDr7Reserved) == 0;
}

bool IsValidGuestState(const GuestContext* c) {
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

long AcquireFatalSnapshotCommitState(VcpuContext* vcpu) {
    if (!vcpu) return HvFatalSnapshotCommitted;
    return InterlockedCompareExchange(&vcpu->FatalSnapshotCommitState,
                                      HvFatalSnapshotEmpty,
                                      HvFatalSnapshotEmpty);
}

u32 ReadNativeTeardownRejectMask(
    const VcpuContext* vcpu) {
    if (!vcpu) return HvNativeTeardownRejectNone;
    return static_cast<u32>(InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->NativeTeardownRejectMask), 0, 0));
}

long ReadFirstExitProbeState(
    const VcpuContext* vcpu) {
    if (!vcpu) return FirstExitProbeFailed;
    return InterlockedCompareExchange(
        const_cast<volatile LONG*>(&vcpu->FirstExitProbeState), 0, 0);
}

u64 PackFirstExitProbeResult(long reason, long action) {
    return static_cast<u64>(static_cast<u32>(reason)) |
           (static_cast<u64>(static_cast<u32>(action)) << 32);
}

void CaptureFirstExitProbeObservation(VcpuContext* vcpu,
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

void FailFirstExitProbeIfActive(VcpuContext* vcpu, u32 cpuId) {
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

void InvalidateValidatedFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
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

void FailFirstExitProbeAtFatalBoundary(VcpuContext* vcpu, u32 cpuId) {
    FailFirstExitProbeIfActive(vcpu, cpuId);
    InvalidateValidatedFirstExitProbe(vcpu, cpuId);
}

void MarkFirstExitProbeVmExitEntered(VcpuContext* vcpu,
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

void CompleteFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
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

bool ArmFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
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

bool VerifyFirstExitProbeReturn(VcpuContext* vcpu, u32 cpuId,
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

bool RunFirstExitProbe(VcpuContext* vcpu, u32 cpuId) {
    if (!ArmFirstExitProbe(vcpu, cpuId)) return false;
    int regs[4] = {};
    __cpuidex(regs, static_cast<int>(kFirstExitProbeLeaf), 0);
    return VerifyFirstExitProbeReturn(vcpu, cpuId, regs);
}

void RequestFatalStop(GuestContext* c) {
    if (!c) return;
    c->AbortVm = 0;
    c->HaltVm = 1;
}

void RequestAuthenticatedUnload(GuestContext* c,
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
    } else if (c && authenticatedUnload) {
        constexpr u32 kFatalTeardownRejectBits =
            static_cast<u32>(HvNativeTeardownRejectVmcsRead) |
            static_cast<u32>(HvNativeTeardownRejectGuestState) |
            static_cast<u32>(HvNativeTeardownRejectCpl) |
            static_cast<u32>(HvNativeTeardownRejectParameters);
        // A normal stop request can arrive while the guest has a transient
        // interruptibility, event-delivery, or descriptor state that cannot be
        // reproduced by the native IRET handoff. Resume and retry those cases.
        // A failed VMCS read or malformed guest state remains a fatal boundary.
        c->AbortVm = 0;
        c->HaltVm = (rejectMask & kFatalTeardownRejectBits) != 0 ? 1 : 0;
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
