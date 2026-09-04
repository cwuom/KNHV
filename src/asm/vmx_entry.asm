; VMX entry, root exception and restore paths
include vmx_asm.inc

extern g_HvVmxOffFailureFlagsAsm:qword

.code

PUBLIC HvHostNmi2
PUBLIC HvHostException0
PUBLIC HvHostException5
PUBLIC HvHostException6
PUBLIC HvHostException7
PUBLIC HvHostException8
PUBLIC HvHostException10
PUBLIC HvHostException11
PUBLIC HvHostException12
PUBLIC HvHostException13
PUBLIC HvHostException14
PUBLIC HvHostException16
PUBLIC HvHostException17
PUBLIC HvHostException18
PUBLIC HvHostException19
PUBLIC HvHostException21
PUBLIC HvVmExitEntryPoint
PUBLIC HvRestoreStateAndReturn

; VMX-root exception evidence offsets. Keep these synchronized with the
; static_asserts on HvHostFaultRecord in common.h. The assembly path writes
; this prefix before calling C++ so a second fault cannot erase the first one.
HOST_FAULT_COMMIT equ 000h
HOST_FAULT_VECTOR equ 004h
HOST_FAULT_ERROR  equ 008h
HOST_FAULT_RIP    equ 010h
HOST_FAULT_RSP    equ 018h
HOST_FAULT_RFLAGS equ 020h
HOST_FAULT_CR2    equ 028h
HOST_FAULT_CR3    equ 030h
HOST_FAULT_CR4    equ 038h
HOST_FAULT_TSC    equ 040h

; error-code and no-error stubs normalize the no-IST root stack to:
;   vector, error, RIP, CS, RFLAGS
; the interrupted RSP is therefore the address immediately above RFLAGS.
; Debug and breakpoint vectors deliberately keep the Windows handlers so KD
; remains usable while the VMX-root diagnostic IDT is active.

; VMX-root NMI isolation stub.  Guest NMIs still execute natively because
; pin-based NMI exiting is disabled.  This handler runs only when an NMI lands
; during the short VMX-root window.  Do not call C/C++, touch VMCS state, or
; use a scratch GPR here: a locked memory increment plus IRETQ keeps the
; interrupted root context byte-for-byte intact while proving whether the
; Windows NMI entry path is the reset trigger.
HvHostNmi2 proc
    lock inc qword ptr [g_HvRootNmiCount]
    iretq
HvHostNmi2 endp

HvHostException0 proc
    push 0
    push 0
    jmp HvHostExceptionCommon
HvHostException0 endp

HvHostException5 proc
    push 0
    push 5
    jmp HvHostExceptionCommon
HvHostException5 endp

HvHostException6 proc
    push 0
    push 6
    jmp HvHostExceptionCommon
HvHostException6 endp

HvHostException7 proc
    push 0
    push 7
    jmp HvHostExceptionCommon
HvHostException7 endp

; #DF, #TS, #NP, #SS, #GP and #PF arrive with a hardware error code.
HvHostException8 proc
    push 8
    jmp HvHostExceptionCommon
HvHostException8 endp

HvHostException10 proc
    push 10
    jmp HvHostExceptionCommon
HvHostException10 endp

HvHostException11 proc
    push 11
    jmp HvHostExceptionCommon
HvHostException11 endp

HvHostException12 proc
    push 12
    jmp HvHostExceptionCommon
HvHostException12 endp

HvHostException13 proc
    push 13
    jmp HvHostExceptionCommon
HvHostException13 endp

HvHostException14 proc
    push 14
    jmp HvHostExceptionCommon
HvHostException14 endp

HvHostException16 proc
    push 0
    push 16
    jmp HvHostExceptionCommon
HvHostException16 endp

; #AC carries an error code. #MC and #XM do not.
HvHostException17 proc
    push 17
    jmp HvHostExceptionCommon
HvHostException17 endp

HvHostException18 proc
    push 0
    push 18
    jmp HvHostExceptionCommon
HvHostException18 endp

HvHostException19 proc
    push 0
    push 19
    jmp HvHostExceptionCommon
HvHostException19 endp

; #CP carries the architectural control-protection error code.
HvHostException21 proc
    push 21
    jmp HvHostExceptionCommon
HvHostException21 endp

HvHostExceptionCommon:
    cli
    cld

    xor eax, eax
    mov edx, 1
    lock cmpxchg dword ptr [g_HvHostFaultRecord + HOST_FAULT_COMMIT], edx
    jne hvHostFaultAlreadyCommitted

    mov eax, dword ptr [rsp]
    mov dword ptr [g_HvHostFaultRecord + HOST_FAULT_VECTOR], eax
    mov rax, qword ptr [rsp + 08h]
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_ERROR], rax
    mov rax, qword ptr [rsp + 10h]
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_RIP], rax
    lea rax, [rsp + 28h]
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_RSP], rax
    mov rax, qword ptr [rsp + 20h]
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_RFLAGS], rax
    mov rax, cr2
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_CR2], rax
    mov rax, cr3
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_CR3], rax
    mov rax, cr4
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_CR4], rax
    rdtsc
    shl rdx, 20h
    or rax, rdx
    mov qword ptr [g_HvHostFaultRecord + HOST_FAULT_TSC], rax
    mfence
    mov dword ptr [g_HvHostFaultRecord + HOST_FAULT_COMMIT], 2

    ; Only the CPU that won the first-fault record may enter C++. A recursive
    ; fault or a simultaneous fault on another CPU must not overwrite the
    ; evidence or race a second bugcheck path against the original failure.
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 20h
    call HvHostExceptionBugCheck

hvHostFaultAlreadyCommitted:

hvHostFaultPark:
    cli
    hlt
    jmp hvHostFaultPark

; HvVmExitEntryPoint
; handles the transition from guest to host
HvVmExitEntryPoint proc
    ; VM-exit does not switch to a Windows thread stack. Disable interrupts
    ; before allocating the private frame so an IRQ cannot enter the kernel
    ; while RSP still points at the VMX host stack.
    cli

    cmp dword ptr [g_HvLaunchVmExitAsmReached], 0
    jne vmExitAsmRecorded
    lock bts dword ptr [g_HvLaunchVmExitAsmReached], 0

vmExitAsmRecorded:
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
    mov qword ptr [rsp + CTX_NATIVE_IDT_BASE], 0
    mov qword ptr [rsp + CTX_NATIVE_IDT_LIMIT], 0
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

    ; VMX does not virtualize XCR0. Capture the guest mask, then switch to the
    ; validated host mask before saving state. Saving with the guest's current
    ; mask would leave a disabled component live in hardware; if the guest
    ; enabled it again later, it could observe the host's value.
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je vmxSaveFxsave
    xor ecx, ecx
    xgetbv
    mov r8d, eax
    mov r9d, edx
    mov rdx, r9
    shl rdx, 20h
    or r8, rdx
    mov [rsp + CTX_GUEST_XCR0], r8

    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv

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
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    or rax, r15
    mov rdx, rax
    shr rdx, 20h
    ; use the 64-bit operand-size form explicitly.  The unsuffixed MASM
    ; mnemonic emits the 32-bit XSAVE format in long mode, which does not
    ; preserve the 64-bit x87 environment used by the Windows kernel
    xsaves64 [rsp]
    jmp short vmxStateSaved

vmxSaveXsave:
    mov qword ptr [rsp + CTX_GUEST_XSS], 0
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    xsave64 [rsp]

    jmp short vmxStateSaved

vmxSaveFxsave:
    mov qword ptr [rsp + CTX_GUEST_XCR0], 0
    mov qword ptr [rsp + CTX_GUEST_XSS], 0
    fxsave64 [rsp]

vmxStateSaved:

    ; Restore the host masks before touching any compiler-generated code.
    ; PrepareHvCallback initializes these per-CPU slots immediately below the
    ; host KERNEL_GS_BASE shadow.
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je vmxHostMasksReady
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

    ; This is the earliest normal C++-safe VM-exit milestone: host KGS, debug
    ; state, XCR0 and XSS are all restored. If KD sees VM-exit assembly entry
    ; without this trace and no root-fault record, the stall is inside the
    ; fixed assembly preservation prefix rather than VmExitHandler.
    mov ecx, HV_TRACE_VMEXIT_HOST_READY
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h

    mov rcx, rsp

    sub rsp, 20h
    call VmExitHandler
    add rsp, 20h

    ; Record the resume boundary while the host XSTATE/GPR contract is still
    ; active.  No C++ call may occur after the final guest restore because a
    ; normal Win64 callee may clobber every volatile guest register and XMM
    ; component before VMRESUME consumes the live processor state.
    cmp qword ptr [rsp + CTX_HALT_VM], 0
    jne vmxPreVmresumeTraceDone
    cmp qword ptr [rsp + CTX_ABORT_VM], 0
    jne vmxPreVmresumeTraceDone
    mov ecx, HV_TRACE_PRE_VMRESUME
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
vmxPreVmresumeTraceDone:

vmxGuestStateCommit:
    ; The handler ran with the host XCR0/XSS contract. Restore the complete
    ; host-saved state first, then switch to the guest mask. This keeps state
    ; for components the guest temporarily disabled from leaking across exits.
    ; A fatal handler cannot provide a valid guest XSTATE image. Do not load
    ; guest-selected XCR0/XSS values on the park or native-teardown branches:
    ; an invalid mask would raise #GP in VMX root before the diagnostic path
    ; can leave VMX.
    cmp qword ptr [rsp + CTX_HALT_VM], 0
    jne vmxStateRestored
    cmp qword ptr [rsp + CTX_ABORT_VM], 0
    jne vmxStateRestored
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je vmxRestoreFxsave
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
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
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    or rax, r15
    mov rdx, rax
    shr rdx, 20h
    xrstors64 [rsp]
    mov rax, [rsp + CTX_GUEST_XSS]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
    mov rax, [rsp + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    jmp short vmxStateRestored

vmxRestoreXsave:
    mov rax, [rsp + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    xrstor64 [rsp]

    mov rax, [rsp + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv

    jmp short vmxStateRestored

vmxRestoreFxsave:
    fxrstor64 [rsp]

vmxStateRestored:

vmExitDebugHoldLoop:
    cmp dword ptr [g_HvVmExitDebugHold], 0
    je vmExitDebugHoldDone
    pause
    jmp vmExitDebugHoldLoop

vmExitDebugHoldDone:

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
    ; A failed VMRESUME returns in VMX root with the same stack pointer. This
    ; commit tail must remain free of calls after guest XSTATE/GPR restoration.
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
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je vmxHaltHostMasksReady
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
    mov ecx, HV_TRACE_PRE_VMXOFF
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    mov rcx, rsp
    sub rsp, 20h
    call HvCaptureFatalSnapshotPreVmxoff
    add rsp, 20h
    mov ecx, HV_TRACE_FATAL_SNAPSHOT_COMPLETE
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    sub rsp, 20h
    call MarkCurrentVcpuParked
    add rsp, 20h
    mov ecx, HV_TRACE_FATAL_PARKED
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    sub rsp, 20h
    call HvClearCurrentVmcsAndRecord
    add rsp, 20h
    test al, al
    jz vmxHaltVmclearFailed
    vmxoff
    jc vmxHaltVmxoffFailed
    jz vmxHaltVmxoffFailed
    mov rax, cr4
    btr rax, 0Dh
    mov cr4, rax
    mov ecx, HV_TRACE_POST_VMXOFF
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h

    ; VMX is off now. Put the Windows IDTR back before KeBugCheckEx so the
    ; ordinary crash path no longer depends on the diagnostic root IDT. Keep
    ; the private IDT on VMXOFF failure, where it is still needed for evidence.
    mov rax, [rsp + CTX_NATIVE_IDT_BASE]
    test rax, rax
    jz vmxHaltBugCheck
    mov r10, rsp
    sub rsp, 20h
    mov rax, [r10 + CTX_NATIVE_IDT_LIMIT]
    mov word ptr [rsp], ax
    mov rax, [r10 + CTX_NATIVE_IDT_BASE]
    mov qword ptr [rsp + 2], rax
    lidt fword ptr [rsp]
    add rsp, 20h
    jmp vmxHaltBugCheck
vmxHaltVmxoffFailed:
    ; Capture VMXOFF's failure flags before any instruction can overwrite them
    ; Bit 63 marks the first-wins slot as committed; bits 0 and 6 retain CF/ZF
    pushfq
    pop rax
    mov rdx, rax
    bts rdx, 3Fh
    xor eax, eax
    lock cmpxchg qword ptr [g_HvVmxOffFailureFlagsAsm], rdx
    jmp vmxHaltBugCheck
vmxHaltVmclearFailed:
    sub rsp, 20h
    call HvFailVmcsClear
    add rsp, 20h
vmxHaltBugCheck:
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
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je vmxResumeFailureHostMasksReady
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
    mov ecx, HV_TRACE_VMRESUME_FAIL
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    cmp qword ptr [rsp + CTX_HALT_VM], 0
    jne vmxHalt
    cmp qword ptr [rsp + CTX_ABORT_VM], 0
    jne vmxAbort
    jmp vmxHalt
HvVmExitEntryPoint endp

; HvRestoreStateAndReturn
; Called while tearing down a temporary guest handoff or an unload request.
; RCX = Pointer to GuestContext
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
    ; vmx does not restore IA32_KERNEL_GS_BASE, so the exit epilogue leaves
    ; the guest value installed until the host value is restored here
    mov rax, [r10 + HOST_KGS_CONTEXT_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_KERNEL_GS_BASE
    wrmsr
    ; the teardown callback runs as ordinary host C++ code. Restore the host
    ; XCR0/XSS contract before entering it, then restore the guest masks after
    ; VMXOFF and before the native IRET handoff.
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je teardownHostMasksReady
    mov rax, [r10 + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    ; restore host IA32_XSS before entering the callback when XSAVES is active
    cmp byte ptr [g_XsavesEnabled], 0
    je teardownHostMasksReady
    mov rax, [r10 + HOST_XSS_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
teardownHostMasksReady:
    sub rsp, 20h
    call MarkCurrentVcpuTearingDown
    add rsp, 20h
    test al, al
    jnz teardownMarkerAuthorized
    ; An authenticated VMCALL is not enough by itself.  If the stop
    ; rendezvous did not publish the one-shot owner token, leave through the
    ; diagnostic park path instead of manufacturing a native IRET frame.
    mov r10, rbx
    mov qword ptr [r10 + CTX_ABORT_VM], 0
    mov qword ptr [r10 + CTX_HALT_VM], 1
    jmp restoreInvalid
teardownMarkerAuthorized:
    mov r10, rbx

    mov r11, [r10 + CTX_GUEST_RSP]
    mov r12, [r10 + CTX_GUEST_CS]
    mov r13, [r10 + CTX_GUEST_SS]
    mov r14, [r10 + CTX_GUEST_RIP]
    mov r15, [r10 + CTX_RFLAGS]

    ; CS and RIP must be valid. In 64-bit mode IRETQ always pops
    ; SS:RSP, even for a CPL0-to-CPL0 return, and Intel permits a null SS when
    ; the target is 64-bit and CPL is not 3. Keep the captured SS verbatim.
    test r12, r12
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

    ; Intel 64-bit IRETQ unconditionally pops RIP, CS, RFLAGS, RSP
    ; and SS, even when returning to CPL0. Build the complete five-qword frame
    ; so the native VMCALL continuation receives its original stack pointer.
restoreRing0:
    lea r8, [r11 - 28h]                   ; complete 64-bit IRETQ frame
    lea r9, [r8 - 100h]                   ; guest stack spill area

    ; Subtracting from a canonical RSP can cross the sign boundary or wrap.
    ; Validate both derived addresses and their ordering before the first
    ; guest-stack store. Canonicality does not prove page presence; the
    ; teardown contract must keep this kernel stack mapped under both CR3s.
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
    cmp r8, r11
    ja restoreInvalid
    cmp r9, r8
    ja restoreInvalid

restoreFrameReady:
    mov [r8 + 00h], r14                   ; RIP
    mov [r8 + 08h], r12                   ; CS
    mov [r8 + 10h], r15                   ; RFLAGS
    mov [r8 + 18h], r11                   ; RSP
    mov [r8 + 20h], r13                   ; SS (may be null at CPL0)

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
    mov rax, [r10 + CTX_NATIVE_IDT_LIMIT]
    mov word ptr [r9 + RST_IDTR_LIMIT], ax
    mov rax, [r10 + CTX_NATIVE_IDT_BASE]
    mov qword ptr [r9 + RST_IDTR_BASE], rax
    mov rsi, r8
    mov rbp, r9

    ; Leave VMX while all host MSRs and the host page table are still active.
    mov ecx, HV_TRACE_PRE_VMXOFF
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    sub rsp, 20h
    call HvClearCurrentVmcsAndRecord
    add rsp, 20h
    test al, al
    jz teardownVmclearFailed
    vmxoff
    jc teardownVmxoffFailed
    jz teardownVmxoffFailed
    mov r10, rbx
    mov ecx, HV_TRACE_POST_VMXOFF
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
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
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je restoreGuestFxsave
    mov rax, [r10 + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    cmp byte ptr [g_XsavesEnabled], 0
    je restoreGuestXsave
    ; Use the fixed compacted layout for teardown as well.  This path returns
    ; to the interrupted Windows context, so restore its current guest XSS
    ; selector after XRSTORS rather than discarding a legal selector change.
    mov r15, qword ptr [g_XsavesMask]
    mov r14, r15
    shr r14, 20h
    mov eax, r15d
    mov edx, r14d
    mov ecx, MSR_IA32_XSS
    wrmsr
    mov rax, [r10 + HOST_XCR0_FRAME_SLOT]
    or rax, r15
    mov rdx, rax
    shr rdx, 20h
    xrstors64 [r10]
    mov rax, [r10 + CTX_GUEST_XSS]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, MSR_IA32_XSS
    wrmsr
    mov rax, [r10 + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv
    jmp short restoreGuestStateDone

restoreGuestXsave:
    mov rax, [r10 + HOST_XCR0_FRAME_SLOT]
    mov rdx, rax
    shr rdx, 20h
    xrstor64 [r10]

    mov rax, [r10 + CTX_GUEST_XCR0]
    mov rdx, rax
    shr rdx, 20h
    mov ecx, 0
    xsetbv

    jmp short restoreGuestStateDone

restoreGuestFxsave:
    fxrstor64 [r10]

restoreGuestStateDone:
    ; restore the guest CET fields selected by the VMCS contract before the
    ; native handoff. the fields are valid only on CET-capable processors
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
    ; HOST_IDTR_BASE uses the private VMX-root table. Restore the exact native
    ; Windows IDTR immediately before the architectural handoff. Interrupts
    ; remain disabled until IRETQ restores the guest RFLAGS.
    lidt fword ptr [r9 + RST_IDTR_LIMIT]

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

teardownVmxoffFailed:
    ; VMXOFF failed, so VMX root and the host stack are still authoritative.
    ; Preserve that diagnosable state instead of clearing VMXE or attempting
    ; the guest CR3/IRET transition with an active VMCS.
    cli
    ; Record the raw VMXOFF flags before calls or stores change them
    pushfq
    pop rax
    mov rdx, rax
    bts rdx, 3Fh
    xor eax, eax
    lock cmpxchg qword ptr [g_HvVmxOffFailureFlagsAsm], rdx
    mov r10, rbx
    mov qword ptr [r10 + CTX_HALT_VM], 1
    mov rcx, r10
    sub rsp, 20h
    call HvCaptureFatalSnapshotPreVmxoff
    add rsp, 20h
    mov ecx, HV_TRACE_FATAL_SNAPSHOT_COMPLETE
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    sub rsp, 20h
    call MarkCurrentVcpuParked
    add rsp, 20h
    mov ecx, HV_TRACE_FATAL_PARKED
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    mov r10, rbx
    mov rcx, r10
    sub rsp, 20h
    call HvFatalBugCheck
    add rsp, 20h
teardownVmxoffFailedLoop:
    hlt
    jmp teardownVmxoffFailedLoop

teardownVmclearFailed:
    sub rsp, 20h
    call HvFailVmcsClear
    add rsp, 20h
    jmp teardownVmxoffFailedLoop

restoreInvalid:
    ; There is no safe architectural return for malformed state.  Park this
    ; processor with interrupts disabled instead of executing a guessed RET or
    ; IRET frame, which would turn the original error into a triple fault.
    cli
    ; No guest continuation is possible here.  Restore host XCR0/XSS before
    ; calling the park marker, whose implementation is normal kernel C++.
    cmp byte ptr [g_XstateMode], XSTATE_SAVE_FXSAVE
    je restoreInvalidHostMasksReady
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
    mov ecx, HV_TRACE_PRE_VMXOFF
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    ; HvTraceCurrentVcpuEvent is a normal Win64 callee and may clobber R10.
    ; Reload the nonvolatile context anchor before passing it to the snapshot.
    mov r10, rbx
    mov rcx, r10
    sub rsp, 20h
    call HvCaptureFatalSnapshotPreVmxoff
    add rsp, 20h
    mov ecx, HV_TRACE_FATAL_SNAPSHOT_COMPLETE
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    mov r10, rbx
    sub rsp, 20h
    call MarkCurrentVcpuParked
    add rsp, 20h
    mov ecx, HV_TRACE_FATAL_PARKED
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    ; the park callback may clobber volatile R10
    ; restore the frame pointer before VMXOFF and the fatal diagnostic call
    mov r10, rbx
    sub rsp, 20h
    call HvClearCurrentVmcsAndRecord
    add rsp, 20h
    test al, al
    jz restoreInvalidVmclearFailed
    vmxoff
    jc restoreInvalidVmxoffFailed
    jz restoreInvalidVmxoffFailed
    mov rax, cr4
    btr rax, 0Dh
    mov cr4, rax
    mov ecx, HV_TRACE_POST_VMXOFF
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    jmp restoreInvalidBugCheck
restoreInvalidVmxoffFailed:
    ; Keep the original VMXOFF CF/ZF in the first-wins diagnostic slot
    pushfq
    pop rax
    mov rdx, rax
    bts rdx, 3Fh
    xor eax, eax
    lock cmpxchg qword ptr [g_HvVmxOffFailureFlagsAsm], rdx
    jmp restoreInvalidBugCheck
restoreInvalidVmclearFailed:
    sub rsp, 20h
    call HvFailVmcsClear
    add rsp, 20h
restoreInvalidBugCheck:
    mov r10, rbx
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

end
