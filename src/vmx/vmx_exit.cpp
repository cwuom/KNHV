// VM-exit dispatch and guest instruction emulation

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
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

// VM-Exit Handling

void InjectGuestException(GuestContext* c, u8 vector, bool hasErrorCode,
                                 u32 errorCode) {
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
        // Both a successful native teardown and a graceful teardown deferral
        // consume this VMCALL instruction. A fatal handler path leaves HaltVm
        // set and must not advance RIP.
        return Ctx->HaltVm == 0;
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

bool SetMsrBitmapIntercept(void* bitmap, u32 msr,
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

bool ConfigureMsrBitmap(VcpuContext* vcpu) {
    if (!vcpu || !vcpu->MsrBitmapVirt) return false;

    // Keep ordinary MSRs native. IA32_XSS is the one guarded selector because
    // the VM-exit XSAVES frame has an immutable supervisor-component mask.
    RtlZeroMemory(vcpu->MsrBitmapVirt, PAGE_SIZE);
    return SetMsrBitmapIntercept(vcpu->MsrBitmapVirt, MSR_IA32_XSS, true, true);
}

u32 ControlMsr(u64 vmxBasic, u32 legacyMsr, u32 trueMsr) {
    return (vmxBasic & VMX_BASIC_TRUE_CONTROLS) ? trueMsr : legacyMsr;
}

u32 ControlMandatoryOn(u32 msr) {
    return static_cast<u32>(__readmsr(msr));
}

u64 GetGpr(const GuestContext* c, u8 reg) {
    switch (reg) {
        case 0: return c->Rax; case 1: return c->Rcx; case 2: return c->Rdx; case 3: return c->Rbx;
        case 4: return c->GuestRsp; case 5: return c->Rbp; case 6: return c->Rsi; case 7: return c->Rdi;
        case 8: return c->R8;  case 9: return c->R9;  case 10: return c->R10; case 11: return c->R11;
        case 12: return c->R12; case 13: return c->R13; case 14: return c->R14; case 15: return c->R15;
        default: return 0;
    }
}

bool SetGpr(GuestContext* c, u8 reg, u64 v) {
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

bool HandleCrAccess(GuestContext* c) {
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
bool HandleXsetbv(GuestContext* c, VcpuContext* vcpu) {
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
    // The assembly entry populated this field at CTX_GUEST_KGS before calling us

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
    // the supported exit range for this handler. A zero or oversized
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
            // treat these unconditional non-root exits as unsupported
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
