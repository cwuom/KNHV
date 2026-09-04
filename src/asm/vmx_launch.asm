; VMX launch transition and VMCALL bridge
include vmx_asm.inc

.code

PUBLIC HvLaunchGuest
PUBLIC GuestStartThunk
PUBLIC EnableHvCallback
PUBLIC HvCall

HvLaunchGuest proc frame
    ; Keep a private failure stack so a VMfailValid/VMfailInvalid return cannot
    ; overwrite the caller's shadow space. Guest RIP/RSP are prepared once by
    ; SetupVmcs and are intentionally not rewritten in this final transition.
    sub rsp, 200h
    .allocstack 200h
    .endprolog
    lock inc dword ptr [g_HvLaunchGuestEntered]

    ; Never execute a VMX instruction after a failed preparation or an
    ; unexpected VMXOFF. The C++ caller treats this token as a non-VMX path.
    mov rax, cr4
    test rax, CR4_VMXE
    jz launchNotVmx

    lock inc dword ptr [g_HvLaunchVmlaunchIssued]
    vmlaunch
    pushfq
    pop rax
    lock inc dword ptr [g_HvLaunchVmlaunchReturned]
    add rsp, 200h
    ret

launchNotVmx:
    mov rax, VMX_LAUNCH_NOT_VMX_MAGIC
    add rsp, 200h
    ret
HvLaunchGuest endp

; guest start and restore thunk
; the launch contract keeps the initial guest stack as a complete register frame.  The
; VMCS guest RIP points here, so a successful VM-entry restores the interrupted
; DPC context and returns to the original caller without executing C++ code in
; VMX non-root mode.
GuestStartThunk proc
    ; Keep this thunk side-effect free under the guest CR3. The restore
    ; path only touches the launch frame before returning to Windows; the first
    ; real VM-exit records guest entry after host state is available.
    movdqu xmm6, xmmword ptr [rsp + 020h]
    movdqu xmm7, xmmword ptr [rsp + 030h]
    movdqu xmm8, xmmword ptr [rsp + 040h]
    movdqu xmm9, xmmword ptr [rsp + 050h]
    movdqu xmm10, xmmword ptr [rsp + 060h]
    movdqu xmm11, xmmword ptr [rsp + 070h]
    movdqu xmm12, xmmword ptr [rsp + 080h]
    movdqu xmm13, xmmword ptr [rsp + 090h]
    movdqu xmm14, xmmword ptr [rsp + 0A0h]
    movdqu xmm15, xmmword ptr [rsp + 0B0h]
    ldmxcsr [rsp + 0C0h]
    add rsp, 100h
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    ; match the restore contract: the VMCS carries the saved DPC
    ; RFLAGS image, so restore it directly and discard the alignment slot.
    popfq
    add rsp, 08h
    ret
GuestStartThunk endp

; IPI launch wrapper
; Keep the save/restore frame identical to the AsmVmxSaveState model:
; an alignment slot, RFLAGS, every GPR, and a private XMM area.  VMLAUNCH
; failure returns through this frame; success enters GuestStartThunk and never
; executes the wrapper's C++ tail in VMX non-root mode.
EnableHvCallback proc
    push 0
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 100h

    ; Keep the first 20h bytes as the Windows x64 shadow space for PrepareHvCallback.
    movdqu xmmword ptr [rsp + 020h], xmm6
    movdqu xmmword ptr [rsp + 030h], xmm7
    movdqu xmmword ptr [rsp + 040h], xmm8
    movdqu xmmword ptr [rsp + 050h], xmm9
    movdqu xmmword ptr [rsp + 060h], xmm10
    movdqu xmmword ptr [rsp + 070h], xmm11
    movdqu xmmword ptr [rsp + 080h], xmm12
    movdqu xmmword ptr [rsp + 090h], xmm13
    movdqu xmmword ptr [rsp + 0A0h], xmm14
    movdqu xmmword ptr [rsp + 0B0h], xmm15
    stmxcsr [rsp + 0C0h]

    ; The original Context is the saved RCX at +168h.  GuestSp is the frame
    ; base, exactly as in the C++ save-state declaration.
    mov rcx, [rsp + 168h]
    lea rdx, [rsp]
    lea r8, GuestStartThunk
    lock inc dword ptr [g_HvLaunchAssemblyEntered]
    ; the launch frame doubles as the guest stack, so its first 20h bytes are
    ; not the caller-owned shadow space required by the Win64 ABI
    ; move the call area below the frame to keep C++ home slots out of saved XMM state
    sub rsp, 20h
    call PrepareHvCallback
    add rsp, 20h
    test al, al
    jz enableHvRestore

    mov ecx, HV_TRACE_PRE_VMLAUNCH
    sub rsp, 20h
    call HvTraceCurrentVcpuEvent
    add rsp, 20h
    mov ecx, HV_FAULT_BEFORE_VMLAUNCH
    sub rsp, 20h
    call HvFaultInjectedCurrent
    add rsp, 20h
    test al, al
    jnz injectedLaunchFailure
    mov ecx, HV_FAULT_VMLAUNCH_FAIL
    sub rsp, 20h
    call HvFaultInjectedCurrent
    add rsp, 20h
    test al, al
    jnz injectedLaunchFailure
    ; publish the per-CPU launched state immediately before
    ; VMLAUNCH because a successful instruction never returns to this frame.
    ; A VMfail path returns here and is then rolled back by AbortHvLaunch.
    sub rsp, 20h
    call MarkCurrentVcpuLaunched
    add rsp, 20h
    test al, al
    jz launchMarkerFailure
    sub rsp, 20h
    call HvLaunchGuest
    add rsp, 20h
    mov rcx, rax
    sub rsp, 20h
    call AbortHvLaunch
    add rsp, 20h
    jmp enableHvRestore

injectedLaunchFailure:
    xor ecx, ecx
    sub rsp, 20h
    call AbortHvLaunch
    add rsp, 20h
    jmp enableHvRestore

launchMarkerFailure:
    mov rcx, VMX_LAUNCH_MARKER_FAILURE_MAGIC
    sub rsp, 20h
    call AbortHvLaunch
    add rsp, 20h

enableHvRestore:
    movdqu xmm6, xmmword ptr [rsp + 020h]
    movdqu xmm7, xmmword ptr [rsp + 030h]
    movdqu xmm8, xmmword ptr [rsp + 040h]
    movdqu xmm9, xmmword ptr [rsp + 050h]
    movdqu xmm10, xmmword ptr [rsp + 060h]
    movdqu xmm11, xmmword ptr [rsp + 070h]
    movdqu xmm12, xmmword ptr [rsp + 080h]
    movdqu xmm13, xmmword ptr [rsp + 090h]
    movdqu xmm14, xmmword ptr [rsp + 0A0h]
    movdqu xmm15, xmmword ptr [rsp + 0B0h]
    ldmxcsr [rsp + 0C0h]
    add rsp, 100h
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    add rsp, 08h
    ret
EnableHvCallback endp

; HvCall (VMCALL Wrapper)
; RCX = Magic, RDX = Command, R8 = Arg1, R9 = Arg2
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
