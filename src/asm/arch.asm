; Created by cwuom on 17 Feb 2026.

.code

extern VmExitHandler:proc
extern PrepareHvCallback:proc
extern AbortHvLaunch:proc
extern MarkCurrentVcpuParked:proc
extern g_LinearAddressBits:byte

MSR_FS_BASE     equ 0C0000100h
MSR_GS_BASE     equ 0C0000101h
MSR_KERNEL_GS_BASE equ 0C0000102h
MSR_IA32_EFER   equ 0C0000080h
MSR_IA32_PAT    equ 00000277h
MSR_IA32_SYSENTER_CS  equ 00000174h
MSR_IA32_SYSENTER_ESP equ 00000175h
MSR_IA32_SYSENTER_EIP equ 00000176h

; VMCS fields used by the launch thunk.  The values are the architectural
; encodings from Intel SDM Vol. 3C, Table B-1.
VMCS_GUEST_RSP  equ 0681Ch
VMCS_GUEST_RIP  equ 0681Eh

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

; The VMX host RSP is HostStackTop. The C++ preparation stores the host
; KERNEL_GS_BASE shadow at HostStackTop - 8, which is offset 0x1178 after the
; VM-exit prologue allocates its 0x1180-byte frame. The slot lies in tail
; padding after the 0x1000-byte XSAVE area and outside GuestContext fields.
HOST_KGS_FRAME_SLOT   equ 01178h
HOST_KGS_CONTEXT_SLOT equ 01178h

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

; ------------------------------------------------------------------------------
; HvVmExitEntryPoint
; handles the transition from guest to host
; ------------------------------------------------------------------------------
HvVmExitEntryPoint proc
    ; 1180h is 64-byte aligned and leaves room for the full GuestContext plus
    ; the reserved host KERNEL_GS_BASE shadow at frame offset 0x1178.
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
    mov rax, [rsp + HOST_KGS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr

    xor ecx, ecx
    xgetbv

    xsave [rsp]

    ; Windows x64 ABI requires DF=0 on entry to C/C++ code.  A guest can
    ; legally run with RFLAGS.DF set when a VM-exit occurs, but that flag is
    ; restored from the VMCS on VMRESUME (or from the IRET frame during
    ; teardown), so clearing it here does not alter guest architectural state.
    cld

    mov rcx, rsp

    sub rsp, 20h
    call VmExitHandler
    add rsp, 20h

    xor ecx, ecx
    xgetbv              ; load XCR0 mask into EDX:EAX

    xrstor [rsp]
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
    ; Keep this CPU interruptible so a later stop/recovery IPI can wake the
    ; HLT loop.  Host CR3/IDT are active after VMXOFF, so servicing an IPI is
    ; safe; leaving IF=0 would strand the processor permanently.
    sti
vmxHaltLoop:
    hlt
    jmp vmxHaltLoop

vmxResumeFailure:
    ; A failed VMRESUME means the VMCS contains invalid guest state or a
    ; malformed control field.  There is no architecturally defined guest
    ; continuation in this case; attempting IRET with the partially-invalid
    ; VMCS is exactly the path that turns an entry failure into a triple fault.
    ; Leave VMX root and park the processor instead.
    jmp vmxHalt
HvVmExitEntryPoint endp

; ------------------------------------------------------------------------------
; HvRestoreStateAndReturn
; Called ONLY during Unload.
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

    ; Restore VMX-managed MSRs while r10 still references host context.
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

    xor ecx, ecx
    xgetbv
    xrstor [r10]

    ; VMXOFF leaves CR4.VMXE set.  Install the guest CR4/CR3 pair only after
    ; all host-context reads are complete.
    vmxoff
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
    sti
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

HvVmRead proc
    vmread rax, rcx
    ret
HvVmRead endp

HvLaunchGuest proc
    ; The normal C++ caller's return address is already at [RSP].  Use that
    ; exact stack and the leaf thunk as the initial guest state.  On a
    ; successful VMLAUNCH the thunk executes RET and returns to the caller's
    ; continuation; on failure VMLAUNCH returns here with CF/ZF in RFLAGS.
    mov rax, rsp
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
    ret

launchVmwriteFailure:
    pushfq
    pop rax
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
    lar eax, ecx
    jz Success
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
    ; VMLAUNCH enters this thunk with the original HvLaunchGuest call frame
    ; as the guest stack.  Returning here pops the normal C++ return address;
    ; this preserves the caller's epilogue and avoids the old
    ; _AddressOfReturnAddress()/RET stack corruption.
    mov rax, VMX_LAUNCH_SUCCESS_MAGIC
    ret
GuestStartThunk endp

; ------------------------------------------------------------------------------
; IPI launch wrapper
; ------------------------------------------------------------------------------
; The C++ preparation routine performs all VMX setup and returns before entry.
; This wrapper owns the call frame used as the initial guest stack.  A
; successful GuestStartThunk RET therefore resumes at launchSuccess, while a
; failed VMLAUNCH returns flags and is cleaned up by AbortHvLaunch.
EnableHvCallback proc
    ; Entry RSP points at the IPI dispatcher's return address.  0A8h keeps the
    ; stack aligned for calls (entry is +8, subtracting 0A8h yields 0 mod 16).
    ; [RSP..1Fh] is the mandatory Windows x64 shadow space; nonvolatile saves
    ; start at 40h so a C++ callee cannot overwrite them.
    sub rsp, 0A8h
    mov [rsp + 40h], rbx
    mov [rsp + 48h], rbp
    mov [rsp + 50h], rsi
    mov [rsp + 58h], rdi
    mov [rsp + 60h], r12
    mov [rsp + 68h], r13
    mov [rsp + 70h], r14
    mov [rsp + 78h], r15

    ; PrepareHvCallback(Context, GuestSp, GuestIp).  HvLaunchGuest overwrites
    ; GUEST_RSP with its own [RSP] return slot immediately before VMLAUNCH.
    lea rdx, [rsp + 80h]
    lea r8, GuestStartThunk
    call PrepareHvCallback
    test eax, eax
    jz enableHvDone

    call HvLaunchGuest
    ; CMP r64, imm64 has no x86-64 encoding; materialize the 64-bit magic in
    ; a volatile register before comparing it.
    mov rdx, VMX_LAUNCH_SUCCESS_MAGIC
    cmp rax, rdx
    je enableHvDone

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
    xor eax, eax
    add rsp, 0A8h
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
