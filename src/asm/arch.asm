; Created by cwuom on 17 Feb 2026.

.code

extern VmExitHandler:proc
extern PrepareHvCallback:proc
extern AbortHvLaunch:proc
extern MarkCurrentVcpuLaunched:proc
extern MarkCurrentVcpuParked:proc
extern MarkCurrentVcpuTearingDown:proc
extern MarkCurrentVcpuStopped:proc
extern HandleVmResumeFailure:proc
extern HvFatalBugCheck:proc
extern g_LinearAddressBits:byte
extern g_CetVmcsEnabled:byte
extern g_XsavesEnabled:byte
extern g_XsavesMask:qword

MSR_FS_BASE     equ 0C0000100h
MSR_GS_BASE     equ 0C0000101h
MSR_KERNEL_GS_BASE equ 0C0000102h
MSR_IA32_EFER   equ 0C0000080h
MSR_IA32_PAT    equ 00000277h
MSR_IA32_DEBUGCTL equ 000001D9h
MSR_IA32_XSS    equ 00000DA0h
MSR_IA32_U_CET  equ 000006A0h
MSR_IA32_S_CET  equ 000006A2h
MSR_IA32_PL0_SSP equ 000006A4h
MSR_IA32_PL1_SSP equ 000006A5h
MSR_IA32_PL2_SSP equ 000006A6h
MSR_IA32_PL3_SSP equ 000006A7h
MSR_IA32_INTERRUPT_SSP_TABLE equ 000006A8h
MSR_IA32_SYSENTER_CS  equ 00000174h
MSR_IA32_SYSENTER_ESP equ 00000175h
MSR_IA32_SYSENTER_EIP equ 00000176h
CR4_CET         equ 0800000h
CR4_VMXE        equ 02000h

; VMCS fields used by the launch thunk.  The values are the architectural
; encodings from Intel SDM Vol. 3C, Table B-1.
VMCS_GUEST_RSP  equ 0681Ch
VMCS_GUEST_RIP  equ 0681Eh
VMCS_GUEST_DR7  equ 0681Ah
VMCS_GUEST_DEBUGCTL equ 02802h

; GuestContext offsets.  Keep these in lockstep with common.h's static_asserts.
CTX_RAX         equ 01000h
CTX_RCX         equ 01008h
CTX_RDX         equ 01010h
CTX_RBX         equ 01018h
CTX_RBP         equ 01020h
CTX_RSI         equ 01028h
CTX_RDI         equ 01030h
CTX_R8          equ 01038h
CTX_R9          equ 01040h
CTX_R10         equ 01048h
CTX_R11         equ 01050h
CTX_R12         equ 01058h
CTX_R13         equ 01060h
CTX_R14         equ 01068h
CTX_R15         equ 01070h
CTX_GUEST_RIP   equ 01078h
CTX_GUEST_RSP   equ 01080h
CTX_RFLAGS      equ 01088h
CTX_GUEST_CS    equ 01090h
CTX_GUEST_SS    equ 01098h
CTX_GUEST_CR3   equ 010A0h
CTX_GUEST_CR4   equ 010A8h
CTX_GUEST_FS    equ 010B0h
CTX_GUEST_GS    equ 010B8h
CTX_GUEST_EFER  equ 010C0h
CTX_GUEST_PAT   equ 010C8h
CTX_GUEST_KGS   equ 010D0h
CTX_ABORT_VM    equ 010D8h
CTX_HALT_VM     equ 010E0h
CTX_GUEST_CR0   equ 010E8h
CTX_SYSENTER_CS  equ 010F0h
CTX_SYSENTER_ESP equ 010F8h
CTX_SYSENTER_EIP equ 01100h
; GuestContext tail slots for state that is not part of the VMCS transition
; contract. Keep these offsets synchronized with common.h static_asserts.
CTX_GUEST_XCR0  equ 01108h
CTX_GUEST_XSS   equ 01110h
CTX_GUEST_S_CET equ 01118h
CTX_GUEST_SSP   equ 01120h
CTX_GUEST_INTR_SSP_TABLE equ 01128h
CTX_GUEST_DR7   equ 01130h
CTX_GUEST_DEBUGCTL equ 01138h

; The VMX host RSP is HostStackTop. The C++ preparation stores the host
; KERNEL_GS_BASE shadow at HostStackTop - 8, which is offset 0x1178 after the
; VM-exit prologue allocates its 0x1180-byte frame. The slot lies in tail
; padding after the 0x1000-byte XSAVE area and outside GuestContext fields.
HOST_KGS_FRAME_SLOT   equ 01178h
HOST_KGS_CONTEXT_SLOT equ 01178h
; Host XCR0/XSS snapshots are stored immediately below the KGS shadow by the
; launch preparation code.  They are per-CPU values and must be initialized
; before VMLAUNCH; the VM-exit path only reads them from this fixed frame.
HOST_XCR0_FRAME_SLOT  equ 01168h
HOST_XSS_FRAME_SLOT   equ 01170h
HOST_DR7_FRAME_SLOT   equ 01158h
HOST_DEBUGCTL_FRAME_SLOT equ 01160h

; HvRestoreStateAndReturn stages state in [guest-rsp - 100h].  This area is
; below the active guest stack and is kept separate from the iret frame near
; guest-rsp.  The stack pointer itself remains the only address used after
; loading guest CR3, so the host VM-exit stack is never dereferenced there.
RST_RAX         equ 000h
RST_RCX         equ 008h
RST_RDX         equ 010h
RST_RBX         equ 018h
RST_RBP         equ 020h
RST_RSI         equ 028h
RST_RDI         equ 030h
RST_R8          equ 038h
RST_R9          equ 040h
RST_R10         equ 048h
RST_R11         equ 050h
RST_R12         equ 058h
RST_R13         equ 060h
RST_R14         equ 068h
RST_R15         equ 070h
RST_CR3         equ 080h
RST_CR4         equ 088h
RST_CR0         equ 078h
RST_GUEST_RSP   equ 090h
RST_GUEST_RIP   equ 098h
RST_RFLAGS      equ 0A0h
RST_GUEST_CS    equ 0A8h
RST_GUEST_SS    equ 0B0h
RST_FRAME_RSP   equ 0B8h
RST_RING        equ 0C0h

; The thunk returns this value in RAX through the normal C++ call return
; address.  Bits used by the VMLAUNCH CF/ZF result are deliberately not relied
; on by this stub; the caller should compare the complete value first.
VMX_LAUNCH_SUCCESS_MAGIC equ 04C41554E43484544h
VMX_LAUNCH_NOT_VMX_MAGIC equ 0BAD0000000000001h
HYPERVISOR_MAGIC         equ 013371337h
VMCALL_UNLOAD             equ 0DEADBEEFh

; ------------------------------------------------------------------------------
; HvVmExitEntryPoint
; handles the transition from guest to host
; ------------------------------------------------------------------------------
HvVmExitEntryPoint proc
    ; VM-exit does not switch to a Windows thread stack. Disable interrupts
    ; before allocating the private frame so an IRQ cannot enter the kernel
    ; while RSP still points at the VMX host stack.
    cli
    ; 1180h is this driver's fixed frame size and is independent of VMCS
    ; encodings; the capability gate keeps the XSAVE area below 1000h.
    sub rsp, 1180h

    mov [rsp + 1000h], rax
    mov [rsp + 1008h], rcx
    mov [rsp + 1010h], rdx
    mov [rsp + 1018h], rbx
    mov [rsp + 1020h], rbp
    mov [rsp + 1028h], rsi
    mov [rsp + 1030h], rdi
    mov [rsp + 1038h], r8
    mov [rsp + 1040h], r9
    mov [rsp + 1048h], r10
    mov [rsp + 1050h], r11
    mov [rsp + 1058h], r12
    mov [rsp + 1060h], r13
    mov [rsp + 1068h], r14
    mov [rsp + 1070h], r15
    mov qword ptr [rsp + CTX_ABORT_VM], 0
    mov qword ptr [rsp + CTX_HALT_VM], 0

    ; IA32_KERNEL_GS_BASE is not loaded by VMX transitions.  A guest
    ; SWAPGS/WRMSR can therefore leave a guest value in the MSR while the
    ; host VM-exit handler is running.  Save the guest value, then restore
    ; the per-CPU host value before touching any C++/Windows code.
    mov ecx, MSR_KERNEL_GS_BASE
    rdmsr
    mov eax, eax
    mov edx, edx
    shl rdx, 20h
    or rax, rdx
    mov [rsp + CTX_GUEST_KGS], rax
    xor r10d, r10d
    mov ecx, VMCS_GUEST_DR7
    vmread rax, rcx
    pushfq
    pop rdx
    test dl, 041h
    jz vmxGuestDr7ReadReady
    xor eax, eax
    mov r10d, 1
vmxGuestDr7ReadReady:
    mov [rsp + CTX_GUEST_DR7], rax
    mov ecx, VMCS_GUEST_DEBUGCTL
    vmread rax, rcx
    pushfq
    pop rdx
    test dl, 041h
    jz vmxGuestDebugctlReadReady
    xor eax, eax
    mov r10d, 1
vmxGuestDebugctlReadReady:
    mov [rsp + CTX_GUEST_DEBUGCTL], rax
    test r10d, r10d
    jz vmxDebugStateReady
    mov qword ptr [rsp + CTX_HALT_VM], 1
vmxDebugStateReady:
    mov rax, [rsp + HOST_KGS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr
    mov rax, [rsp + HOST_DR7_FRAME_SLOT]
    mov dr7, rax
    mov rax, [rsp + HOST_DEBUGCTL_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_DEBUGCTL
    wrmsr

    ; VMX does not virtualize XCR0.  Capture it before switching to the host
    ; mask used by the C++ exit handler. IA32_XSS is read only on the optional
    ; XSAVES path; older processors may fault on that MSR.
    xor ecx, ecx
    xgetbv
    mov r8d, eax
    mov r9d, edx
    mov rdx, r9
    shl rdx, 20h
    or r8, rdx
    mov [rsp + CTX_GUEST_XCR0], r8

    cmp byte ptr [g_XsavesEnabled], 0
    je vmxSaveXsave
    mov ecx, MSR_IA32_XSS
    rdmsr
    mov r8d, eax
    mov r9d, edx
    mov rdx, r9
    shl rdx, 20h
    or r8, rdx
    mov [rsp + CTX_GUEST_XSS], r8
    ; Save with the immutable virtual XSS mask, not the guest's current
    ; selector. This keeps the compacted XSAVE layout identical across exits
    ; while still allowing the guest to change IA32_XSS architecturally.
    mov r15, qword ptr [g_XsavesMask]
    mov r14, r15
    shr r14, 20h
    mov eax, r15d
    mov edx, r14d
    mov ecx, MSR_IA32_XSS
    wrmsr
    mov rax, [rsp + CTX_GUEST_XCR0]
    or rax, r15
    mov rdx, rax
    shr rdx, 20h
    xsaves [rsp]
    jmp short vmxStateSaved

vmxSaveXsave:
    mov qword ptr [rsp + CTX_GUEST_XSS], 0
    mov rax, [rsp + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    xsave [rsp]

vmxStateSaved:

    ; Restore the host masks before touching any compiler-generated code.
    ; PrepareHvCallback initializes these per-CPU slots immediately below the
    ; host KERNEL_GS_BASE shadow.
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv

    cmp byte ptr [g_XsavesEnabled], 0
    je vmxHostMasksReady
    mov rax, [rsp + HOST_XSS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
vmxHostMasksReady:

    ; Windows x64 ABI requires DF=0 on entry to C/C++ code.  A guest can
    ; legally run with RFLAGS.DF set when a VM-exit occurs, but that flag is
    ; restored from the VMCS on VMRESUME (or from the IRET frame during
    ; teardown), so clearing it here does not alter guest architectural state.
    cld

    mov rcx, rsp

    sub rsp, 20h
    call VmExitHandler
    add rsp, 20h

    ; The handler ran with the host XCR0/XSS contract. Restore the guest mask
    ; and state frame before inspecting the VM-exit action flags.
    mov rax, [rsp + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv

    cmp byte ptr [g_XsavesEnabled], 0
    je vmxRestoreXsave
    ; XRSTORS must use the same compacted mask as XSAVES. Restore the guest
    ; IA32_XSS value only after the state image has been consumed.
    mov r15, qword ptr [g_XsavesMask]
    mov r14, r15
    shr r14, 20h
    mov eax, r15d
    mov edx, r14d
    mov ecx, MSR_IA32_XSS
    wrmsr
    mov rax, [rsp + CTX_GUEST_XCR0]
    or rax, r15
    mov rdx, rax
    shr rdx, 20h
    xrstors [rsp]
    mov rax, [rsp + CTX_GUEST_XSS]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
    jmp short vmxStateRestored

vmxRestoreXsave:
    mov rax, [rsp + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    xrstor [rsp]

vmxStateRestored:
    ; Windows x64 C/C++ code requires DF=0.  RFLAGS (including the guest's
    ; original DF) is restored by VMRESUME or the IRET teardown path, so this
    ; only normalizes the temporary VMX-root execution context.
    cld

    ; An abort must never execute VMRESUME.  The VMCS still contains the
    ; guest state, so the common restoration path can safely turn VMX off and
    ; jump back to the exact guest RIP/RSP.
    cmp qword ptr [rsp + CTX_HALT_VM], 0
    jne vmxHalt
    cmp qword ptr [rsp + CTX_ABORT_VM], 0
    jne vmxAbort

    ; Restore the guest's KERNEL_GS_BASE before VMRESUME.  VMX does not do
    ; this automatically, and leaving the host value in place breaks the
    ; guest's next SWAPGS/context switch.
    mov rax, [rsp + CTX_GUEST_KGS]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr

    mov rax, [rsp + 1000h]
    mov rcx, [rsp + 1008h]
    mov rdx, [rsp + 1010h]
    mov rbx, [rsp + 1018h]
    mov rbp, [rsp + 1020h]
    mov rsi, [rsp + 1028h]
    mov rdi, [rsp + 1030h]
    mov r8,  [rsp + 1038h]
    mov r9,  [rsp + 1040h]
    mov r10, [rsp + 1048h]
    mov r11, [rsp + 1050h]
    mov r12, [rsp + 1058h]
    mov r13, [rsp + 1060h]
    mov r14, [rsp + 1068h]
    mov r15, [rsp + 1070h]

    ; Keep rsp at the GuestContext until VMRESUME has definitively succeeded.
    ; A failed VMRESUME returns in VMX root with the same stack pointer; adding
    ; 1100h first would make the caller pass the host return stack as context.
    vmresume
    jc vmxResumeFailure
    jz vmxResumeFailure
    ; Intel specifies CF/ZF for a VMRESUME failure.  Treat any unexpected
    ; return as failure as well; executing an arbitrary RET here is unsafe.
    jmp vmxResumeFailure

vmxAbort:
    test byte ptr [rsp + CTX_GUEST_CS], 3
    jnz vmxHalt
    mov rcx, rsp
    jmp HvRestoreStateAndReturn

vmxHalt:
    ; Fatal VM-exits (triple fault/invalid guest state) have no valid guest
    ; continuation.  Leave VMX root, clear VMXE, and park this processor
    ; without touching guest CR3 or the VM-exit context.
    cli
    ; vmxHalt can be reached after the guest masks were restored (for example
    ; an unsupported VM-exit or a VMRESUME failure).  Keep the park marker and
    ; all subsequent root-mode instructions on the host XCR0/XSS contract.
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    cmp byte ptr [g_XsavesEnabled], 0
    je vmxHaltHostMasksReady
    mov rax, [rsp + HOST_XSS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
vmxHaltHostMasksReady:
    ; vmxResumeFailure reaches this label after the normal path has already
    ; installed the guest KERNEL_GS_BASE.  Restore the host value before the
    ; C++ marker call; otherwise GS-relative kernel accesses can fault while
    ; this CPU is being parked.
    mov rax, [rsp + HOST_KGS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr
    sub rsp, 20h
    call MarkCurrentVcpuParked
    add rsp, 20h
    vmxoff
    mov rax, cr4
    btr rax, 0Dh
    mov cr4, rax
    mov rcx, rsp
    sub rsp, 20h
    call HvFatalBugCheck
    add rsp, 20h
    ; Keep interrupts disabled while parked. The current RSP is the private
    ; VMX stack, not a Windows thread stack, so an IRQ here could enter the
    ; kernel on an invalid stack and create a second fault.
vmxHaltLoop:
    hlt
    jmp vmxHaltLoop

vmxResumeFailure:
    ; A failed VMRESUME means the VMCS contains invalid guest state or a
    ; malformed control field.  Ask C++ to validate the saved frame before
    ; choosing native teardown; only an invalid frame falls through to park.
    pushfq
    pop rbx                         ; preserve VMRESUME CF/ZF flags
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    cmp byte ptr [g_XsavesEnabled], 0
    je vmxResumeFailureHostMasksReady
    mov rax, [rsp + HOST_XSS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
vmxResumeFailureHostMasksReady:
    mov rax, [rsp + HOST_KGS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr
    mov rcx, rsp
    mov rdx, rbx
    sub rsp, 20h
    call HandleVmResumeFailure
    add rsp, 20h
    cmp qword ptr [rsp + CTX_HALT_VM], 0
    jne vmxHalt
    cmp qword ptr [rsp + CTX_ABORT_VM], 0
    jne vmxAbort
    jmp vmxHalt
HvVmExitEntryPoint endp

; ------------------------------------------------------------------------------
; HvRestoreStateAndReturn
; Called while tearing down a temporary guest handoff or an unload request.
; RCX = Pointer to GuestContext
; ------------------------------------------------------------------------------
HvRestoreStateAndReturn proc
    ; The C++ handler calls this routine without returning when VMX is being
    ; torn down.  Copy every value needed after CR3 is changed into a spill
    ; area below the guest return frame.  The VM-exit context lives on the host
    ; stack and may not be mapped by guest page tables.
    ; Interrupts must remain disabled until IRETQ restores the guest RFLAGS;
    ; otherwise an interrupt between VMXOFF and CR3/segment restoration could
    ; vector through the host IDT while executing under guest address space.
    cli
    mov r10, rcx                         ; host GuestContext pointer
    mov rbx, r10
    sub rsp, 20h
    call MarkCurrentVcpuTearingDown
    add rsp, 20h
    mov r10, rbx

    mov r11, [r10 + CTX_GUEST_RSP]
    mov r12, [r10 + CTX_GUEST_CS]
    mov r13, [r10 + CTX_GUEST_SS]
    mov r14, [r10 + CTX_GUEST_RIP]
    mov r15, [r10 + CTX_RFLAGS]

    ; Null CS/SS or a null RIP cannot form an interrupt-return frame.  Reject
    ; them before any guest-stack stores so malformed VMCS state cannot turn
    ; into a #GP/#DF cascade after VMXOFF.
    test r12, r12
    jz restoreInvalid
    test r13, r13
    jz restoreInvalid
    test r14, r14
    jz restoreInvalid

    ; Reject non-canonical control-flow addresses before touching guest memory.
    mov rax, r11
    mov rdx, rax
    movzx ecx, byte ptr [g_LinearAddressBits]
    cmp ecx, 57
    je restoreRspCanonical57
    shl rdx, 10h
    sar rdx, 10h
    jmp short restoreRspCanonicalCompare
restoreRspCanonical57:
    shl rdx, 7
    sar rdx, 7
restoreRspCanonicalCompare:
    cmp rdx, rax
    jne restoreInvalid
    mov rax, r14
    mov rdx, rax
    movzx ecx, byte ptr [g_LinearAddressBits]
    cmp ecx, 57
    je restoreRipCanonical57
    shl rdx, 10h
    sar rdx, 10h
    jmp short restoreRipCanonicalCompare
restoreRipCanonical57:
    shl rdx, 7
    sar rdx, 7
restoreRipCanonicalCompare:
    cmp rdx, rax
    jne restoreInvalid

    mov eax, r12d
    and eax, 3
    mov ecx, r13d
    and ecx, 3
    cmp eax, ecx
    jne restoreInvalid
    ; The frame/spill calculations below subtract from GuestRsp.  Reject a
    ; low value before selecting the ring-specific frame layout.
    cmp r11, 128h
    jb restoreInvalid
    cmp eax, 0
    je restoreRing0
    ; The native teardown callback always runs at CPL0.  There is no safe
    ; ring-3 stack/page-table transition in this driver, so reject it rather
    ; than manufacturing an IRET frame that could fault under KPTI.
    jmp restoreInvalid

    ; iretq pops RIP, CS, RFLAGS and, for CPL3, RSP and SS.  Build the frame
    ; while the host page table is active.  The 0x100-byte gap below it stores
    ; all GPRs and control values.
    lea r8, [r11 - 28h]                   ; CPL3 five-word frame
    mov [r8 + 00h], r14
    mov [r8 + 08h], r12
    mov [r8 + 10h], r15
    mov [r8 + 18h], r11
    mov [r8 + 20h], r13
    jmp short restoreFrameReady

restoreRing0:
    lea r8, [r11 - 18h]                   ; CPL0 three-word frame
    mov [r8 + 00h], r14
    mov [r8 + 08h], r12
    mov [r8 + 10h], r15

restoreFrameReady:
    lea r9, [r8 - 100h]                   ; guest stack spill area

    ; Subtracting from a canonical RSP can cross the 48-bit sign boundary.
    ; Validate both derived addresses before the first guest-stack store.
    mov rax, r8
    mov rdx, rax
    movzx ecx, byte ptr [g_LinearAddressBits]
    cmp ecx, 57
    je restoreFrameCanonical57
    shl rdx, 10h
    sar rdx, 10h
    jmp short restoreFrameCanonicalCompare
restoreFrameCanonical57:
    shl rdx, 7
    sar rdx, 7
restoreFrameCanonicalCompare:
    cmp rdx, rax
    jne restoreInvalid
    mov rax, r9
    mov rdx, rax
    movzx ecx, byte ptr [g_LinearAddressBits]
    cmp ecx, 57
    je restoreSpillCanonical57
    shl rdx, 10h
    sar rdx, 10h
    jmp short restoreSpillCanonicalCompare
restoreSpillCanonical57:
    shl rdx, 7
    sar rdx, 7
restoreSpillCanonicalCompare:
    cmp rdx, rax
    jne restoreInvalid

    mov rax, [r10 + CTX_RAX]
    mov [r9 + RST_RAX], rax
    mov rax, [r10 + CTX_RCX]
    mov [r9 + RST_RCX], rax
    mov rax, [r10 + CTX_RDX]
    mov [r9 + RST_RDX], rax
    mov rax, [r10 + CTX_RBX]
    mov [r9 + RST_RBX], rax
    mov rax, [r10 + CTX_RBP]
    mov [r9 + RST_RBP], rax
    mov rax, [r10 + CTX_RSI]
    mov [r9 + RST_RSI], rax
    mov rax, [r10 + CTX_RDI]
    mov [r9 + RST_RDI], rax
    mov rax, [r10 + CTX_R8]
    mov [r9 + RST_R8], rax
    mov rax, [r10 + CTX_R9]
    mov [r9 + RST_R9], rax
    mov rax, [r10 + CTX_R10]
    mov [r9 + RST_R10], rax
    mov rax, [r10 + CTX_R11]
    mov [r9 + RST_R11], rax
    mov rax, [r10 + CTX_R12]
    mov [r9 + RST_R12], rax
    mov rax, [r10 + CTX_R13]
    mov [r9 + RST_R13], rax
    mov rax, [r10 + CTX_R14]
    mov [r9 + RST_R14], rax
    mov rax, [r10 + CTX_R15]
    mov [r9 + RST_R15], rax

    mov rax, [r10 + CTX_GUEST_CR3]
    mov [r9 + RST_CR3], rax
    mov rax, [r10 + CTX_GUEST_CR4]
    mov [r9 + RST_CR4], rax
    mov rax, [r10 + CTX_GUEST_CR0]
    mov [r9 + RST_CR0], rax
    mov [r9 + RST_GUEST_RSP], r11
    mov [r9 + RST_GUEST_RIP], r14
    mov [r9 + RST_RFLAGS], r15
    mov [r9 + RST_GUEST_CS], r12
    mov [r9 + RST_GUEST_SS], r13
    mov [r9 + RST_FRAME_RSP], r8
    mov rsi, r8
    mov rbp, r9

    ; Leave VMX while all host MSRs and the host page table are still active.
    vmxoff
    mov r10, rbx
    sub rsp, 20h
    call MarkCurrentVcpuStopped
    add rsp, 20h
    mov r10, rbx
    mov r9, rbp
    mov r8, rsi

    ; Restore VMX-managed MSRs after the lifecycle marker has run.
    mov rax, [r10 + CTX_GUEST_DR7]
    mov dr7, rax
    mov ecx, MSR_IA32_DEBUGCTL
    mov rax, [r10 + CTX_GUEST_DEBUGCTL]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_FS_BASE
    mov rax, [r10 + CTX_GUEST_FS]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_GS_BASE
    mov rax, [r10 + CTX_GUEST_GS]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_KERNEL_GS_BASE
    mov rax, [r10 + CTX_GUEST_KGS]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_IA32_EFER
    mov rax, [r10 + CTX_GUEST_EFER]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_IA32_PAT
    mov rax, [r10 + CTX_GUEST_PAT]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_IA32_SYSENTER_CS
    mov rax, [r10 + CTX_SYSENTER_CS]
    xor edx, edx
    wrmsr
    mov ecx, MSR_IA32_SYSENTER_ESP
    mov rax, [r10 + CTX_SYSENTER_ESP]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_IA32_SYSENTER_EIP
    mov rax, [r10 + CTX_SYSENTER_EIP]
    mov rdx, rax
    shr rdx, 20h
    wrmsr

    ; The teardown path returns to the guest, so use the guest masks captured
    ; by the VM-exit entry rather than the host masks used by C++.
    mov rax, [r10 + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    cmp byte ptr [g_XsavesEnabled], 0
    je restoreGuestXsave
    ; Use the fixed compacted layout for teardown as well, then expose the
    ; guest selector after XRSTORS has restored CET_U state.
    mov r15, qword ptr [g_XsavesMask]
    mov r14, r15
    shr r14, 20h
    mov eax, r15d
    mov edx, r14d
    mov ecx, MSR_IA32_XSS
    wrmsr
    mov rax, [r10 + CTX_GUEST_XCR0]
    or rax, r15
    mov rdx, rax
    shr rdx, 20h
    xrstors [r10]
    mov rax, [r10 + CTX_GUEST_XSS]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
    jmp short restoreGuestStateDone

restoreGuestXsave:
    mov rax, [r10 + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    xrstor [r10]

restoreGuestStateDone:

    ; Keep the guest XSS that was restored above for the final IRET context.

    ; The CET VMCS path is disabled for the current contract. Keep the writes
    ; conditional so a future CET implementation cannot fault on old Intel.
    cmp byte ptr [g_CetVmcsEnabled], 0
    je restoreGuestCetDone
    mov ecx, MSR_IA32_S_CET
    mov rax, [r10 + CTX_GUEST_S_CET]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_IA32_PL0_SSP
    mov rax, [r10 + CTX_GUEST_SSP]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
    mov ecx, MSR_IA32_INTERRUPT_SSP_TABLE
    mov rax, [r10 + CTX_GUEST_INTR_SSP_TABLE]
    mov rdx, rax
    shr rdx, 20h
    wrmsr
restoreGuestCetDone:

    ; VMXOFF leaves CR4.VMXE set. Install the guest CR4/CR3 pair only after
    ; all host-context reads and lifecycle callbacks are complete.
    mov rax, [r9 + RST_CR0]
    mov cr0, rax
    mov rax, [r9 + RST_CR4]
    btr rax, 0Dh
    mov cr4, rax
    mov rax, [r9 + RST_CR3]
    mov cr3, rax

    ; Never dereference r10/r9 after CR3 changes.  r8 still points to the
    ; guest frame and is therefore used to derive the guest spill pointer.
    mov rsp, r8
    lea r11, [rsp - 100h]

    mov rax, [r11 + RST_RAX]
    mov rcx, [r11 + RST_RCX]
    mov rdx, [r11 + RST_RDX]
    mov rbx, [r11 + RST_RBX]
    mov rbp, [r11 + RST_RBP]
    mov rsi, [r11 + RST_RSI]
    mov rdi, [r11 + RST_RDI]
    mov r8,  [r11 + RST_R8]
    mov r9,  [r11 + RST_R9]
    mov r10, [r11 + RST_R10]
    mov r12, [r11 + RST_R12]
    mov r13, [r11 + RST_R13]
    mov r14, [r11 + RST_R14]
    mov r15, [r11 + RST_R15]
    mov r11, [r11 + RST_R11]
    iretq

restoreInvalid:
    ; There is no safe architectural return for malformed state.  Park this
    ; processor with interrupts disabled instead of executing a guessed RET or
    ; IRET frame, which would turn the original error into a triple fault.
    cli
    ; No guest continuation is possible here.  Restore host XCR0/XSS before
    ; calling the park marker, whose implementation is normal kernel C++.
    mov rax, [r10 + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    cmp byte ptr [g_XsavesEnabled], 0
    je restoreInvalidHostMasksReady
    mov rax, [r10 + HOST_XSS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
restoreInvalidHostMasksReady:
    ; vmxAbort reaches this path before the normal VMRESUME epilogue restores
    ; the host KERNEL_GS_BASE.  Restore the host per-CPU value before invoking
    ; the C++ marker, whose KPCR access is GS-relative.
    ; r10 points at the VM-exit GuestContext/frame base (the XSAVE area starts
    ; at offset zero), so the host shadow is in its reserved tail slot.
    mov rax, [r10 + HOST_KGS_CONTEXT_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr
    sub rsp, 20h
    call MarkCurrentVcpuParked
    add rsp, 20h
    vmxoff
    mov rax, cr4
    btr rax, 0Dh
    mov cr4, rax
    mov rcx, r10
    sub rsp, 20h
    call HvFatalBugCheck
    add rsp, 20h
    ; Keep interrupts disabled while parked for the same private-stack reason
    ; as the VM-exit fatal path above.
restoreInvalidLoop:
    hlt
    jmp restoreInvalidLoop
HvRestoreStateAndReturn endp

; standard VMX intrinsics
HvVmxOn proc
    vmxon qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmxOn endp

HvVmxOff proc
    vmxoff
    ret
HvVmxOff endp

HvVmClear proc
    vmclear qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmClear endp

HvVmPtrLd proc
    vmptrld qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmPtrLd endp

HvVmWrite proc
    vmwrite rcx, rdx
    pushfq
    pop rax
    ret
HvVmWrite endp

; RCX = VMCS field, RDX = output value. RAX returns VMREAD flags.
HvVmReadChecked proc
    vmread r8, rcx
    pushfq
    pop rax
    mov [rdx], r8
    ret
HvVmReadChecked endp

HvLaunchGuest proc frame
    ; Keep the caller return slot at the top of a private area.  The VMXOFF
    ; restore path builds an IRET frame and a register spill below guest RSP.
    ; Without this reservation those writes would corrupt the IPI dispatcher
    ; stack before the guest RET reaches the wrapper continuation.
    sub rsp, 200h
    .allocstack 200h
    .endprolog

    ; Never execute a VMX instruction after a failed preparation or an
    ; unexpected VMXOFF. The C++ caller treats this token as a non-VMX path.
    mov rax, cr4
    test rax, CR4_VMXE
    jz launchNotVmx

    ; GuestStartThunk executes a RET.  The call to HvLaunchGuest has already
    ; pushed the wrapper continuation at [RSP+200h]; point guest RSP at that
    ; return slot so the successful VM-entry returns to enableHvDone exactly
    ; as the original call would.  The call return slot is exactly [RSP+200h]
    ; after this thunk's private stack reservation.
    mov rax, rsp
    add rax, 200h
    mov ecx, VMCS_GUEST_RSP
    mov rdx, rax
    vmwrite rcx, rdx
    jc launchVmwriteFailure
    jz launchVmwriteFailure

    lea rdx, GuestStartThunk
    mov ecx, VMCS_GUEST_RIP
    vmwrite rcx, rdx
    jc launchVmwriteFailure
    jz launchVmwriteFailure

    vmlaunch
    pushfq
    pop rax
    add rsp, 200h
    ret

launchVmwriteFailure:
    pushfq
    pop rax
    add rsp, 200h
    ret

launchNotVmx:
    mov rax, VMX_LAUNCH_NOT_VMX_MAGIC
    add rsp, 200h
    ret
HvLaunchGuest endp

; Segment Helpers
GetCs proc
    mov ax, cs
    ret
GetCs endp
GetDs proc
    mov ax, ds
    ret
GetDs endp
GetEs proc
    mov ax, es
    ret
GetEs endp
GetSs proc
    mov ax, ss
    ret
GetSs endp
GetFs proc
    mov ax, fs
    ret
GetFs endp
GetGs proc
    mov ax, gs
    ret
GetGs endp
GetTr proc
    str ax
    ret
GetTr endp
GetLdtr proc
    sldt ax
    ret
GetLdtr endp
GetGdtBase proc
    sub rsp, 10h
    sgdt [rsp]
    mov rax, [rsp+2]
    add rsp, 10h
    ret
GetGdtBase endp
GetGdtLimit proc
    sub rsp, 10h
    sgdt [rsp]
    mov ax, [rsp]
    add rsp, 10h
    ret
GetGdtLimit endp
GetIdtBase proc
    sub rsp, 10h
    sidt [rsp]
    mov rax, [rsp+2]
    add rsp, 10h
    ret
GetIdtBase endp
GetIdtLimit proc
    sub rsp, 10h
    sidt [rsp]
    mov ax, [rsp]
    add rsp, 10h
    ret
GetIdtLimit endp
GetRflags proc
    pushfq
    pop rax
    ret
GetRflags endp
GetDr7 proc
    mov rax, dr7
    ret
GetDr7 endp

; u32 HvGetSegmentLimit(u16 Selector)
HvGetSegmentLimit proc
    lsl eax, ecx
    jz  Success
    xor eax, eax
Success:
    ret
HvGetSegmentLimit endp

; u32 HvGetSegmentAr(u16 Selector)
HvGetSegmentAr proc
    test ecx, 0FFF8h
    jz Unusable
    lar eax, ecx
    jz Success
Unusable:
    mov eax, 10000h
    ret
Success:
    shr eax, 8
    and eax, 0F0FFh
    ret
HvGetSegmentAr endp

; ------------------------------------------------------------------------------
; Guest Start Thunk
; ------------------------------------------------------------------------------
GuestStartThunk proc
    ; VMLAUNCH does not return through the HvLaunchGuest call frame. Returning
    ; directly to that frame's continuation leaves the monitor active and lets
    ; the IPI wrapper return to Windows in VMX non-root mode. StopHypervisor()
    ; later uses the reserved VMCALL path to leave VMX on each processor.
    mov rax, VMX_LAUNCH_SUCCESS_MAGIC
    ret
GuestStartThunk endp

; ------------------------------------------------------------------------------
; IPI launch wrapper
; ------------------------------------------------------------------------------
; The C++ preparation routine performs all VMX setup and returns before entry.
; This wrapper owns the call frame used as the initial guest stack.  A
; successful GuestStartThunk RET therefore resumes at enableHvDone while VMX
; remains active, while a failed VMLAUNCH returns flags and is cleaned up by
; AbortHvLaunch.
EnableHvCallback proc frame
    ; Entry RSP points at the IPI dispatcher's return address.  148h keeps the
    ; stack aligned for calls and reserves 0A0h bytes for XMM6-XMM15, which are
    ; nonvolatile in the Windows x64 ABI (entry is +8, subtracting 148h yields
    ; 0 mod 16).
    ; [RSP..1Fh] is the mandatory Windows x64 shadow space; nonvolatile saves
    ; start at 40h so a C++ callee cannot overwrite them.
    sub rsp, 148h
    .allocstack 148h
    mov [rsp + 40h], rbx
    .savereg rbx, 40h
    mov [rsp + 48h], rbp
    .savereg rbp, 48h
    mov [rsp + 50h], rsi
    .savereg rsi, 50h
    mov [rsp + 58h], rdi
    .savereg rdi, 58h
    mov [rsp + 60h], r12
    .savereg r12, 60h
    mov [rsp + 68h], r13
    .savereg r13, 68h
    mov [rsp + 70h], r14
    .savereg r14, 70h
    mov [rsp + 78h], r15
    .savereg r15, 78h
    movdqu xmmword ptr [rsp + 080h], xmm6
    .savexmm128 xmm6, 080h
    movdqu xmmword ptr [rsp + 090h], xmm7
    .savexmm128 xmm7, 090h
    movdqu xmmword ptr [rsp + 0A0h], xmm8
    .savexmm128 xmm8, 0A0h
    movdqu xmmword ptr [rsp + 0B0h], xmm9
    .savexmm128 xmm9, 0B0h
    movdqu xmmword ptr [rsp + 0C0h], xmm10
    .savexmm128 xmm10, 0C0h
    movdqu xmmword ptr [rsp + 0D0h], xmm11
    .savexmm128 xmm11, 0D0h
    movdqu xmmword ptr [rsp + 0E0h], xmm12
    .savexmm128 xmm12, 0E0h
    movdqu xmmword ptr [rsp + 0F0h], xmm13
    .savexmm128 xmm13, 0F0h
    movdqu xmmword ptr [rsp + 100h], xmm14
    .savexmm128 xmm14, 100h
    movdqu xmmword ptr [rsp + 110h], xmm15
    .savexmm128 xmm15, 110h
    .endprolog

    ; PrepareHvCallback(Context, GuestSp, GuestIp).  The future call to
    ; HvLaunchGuest writes its return slot at [RSP-8]; pass that slot to the
    ; VMCS setup so the diagnostic guest RSP matches the VMX launch path.
    lea rdx, [rsp - 8]
    lea r8, GuestStartThunk
    call PrepareHvCallback
    ; PrepareHvCallback is an explicit ULONG contract. Test the low byte as
    ; well so older binaries that still return a C++ bool fail closed.
    test al, al
    jz enableHvDone

    call HvLaunchGuest
    ; CMP r64, imm64 has no x86-64 encoding; materialize the 64-bit magic in
    ; a volatile register before comparing it.
    mov rdx, VMX_LAUNCH_SUCCESS_MAGIC
    cmp rax, rdx
    jne launchFailed
    call MarkCurrentVcpuLaunched
    jmp enableHvDone

launchFailed:
    mov rcx, rax
    call AbortHvLaunch

enableHvDone:
    mov rbx, [rsp + 40h]
    mov rbp, [rsp + 48h]
    mov rsi, [rsp + 50h]
    mov rdi, [rsp + 58h]
    mov r12, [rsp + 60h]
    mov r13, [rsp + 68h]
    mov r14, [rsp + 70h]
    mov r15, [rsp + 78h]
    movdqu xmm6, xmmword ptr [rsp + 080h]
    movdqu xmm7, xmmword ptr [rsp + 090h]
    movdqu xmm8, xmmword ptr [rsp + 0A0h]
    movdqu xmm9, xmmword ptr [rsp + 0B0h]
    movdqu xmm10, xmmword ptr [rsp + 0C0h]
    movdqu xmm11, xmmword ptr [rsp + 0D0h]
    movdqu xmm12, xmmword ptr [rsp + 0E0h]
    movdqu xmm13, xmmword ptr [rsp + 0F0h]
    movdqu xmm14, xmmword ptr [rsp + 100h]
    movdqu xmm15, xmmword ptr [rsp + 110h]
    xor eax, eax
    add rsp, 148h
    ret
EnableHvCallback endp

; ------------------------------------------------------------------------------
; HvCall (VMCALL Wrapper)
; RCX = Magic, RDX = Command, R8 = Arg1, R9 = Arg2
; ------------------------------------------------------------------------------
HvCall proc
    ; Reserve a private continuation area for the unload VMCALL.  HvRestore
    ; builds its IRET frame and spill below the guest RSP; placing that RSP at
    ; the top of this 0x200-byte allocation prevents the restore path from
    ; overwriting StopHvCallback's caller frame or shadow space.
    sub rsp, 200h
    add rsp, 1E0h
    vmcall
    xor rax, rax
    add rsp, 20h
    ret
HvCall endp

end
