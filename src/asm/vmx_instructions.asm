; VMX instruction wrappers and descriptor accessors
include vmx_asm.inc

.data
align 8
PUBLIC g_HvVmxOffFailureFlagsAsm
g_HvVmxOffFailureFlagsAsm dq 0

.code

PUBLIC HvVmxOn
PUBLIC HvVmxOff
PUBLIC HvVmClear
PUBLIC HvVmPtrSt
PUBLIC HvVmPtrLd
PUBLIC HvVmWrite
PUBLIC HvVmReadChecked
PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetTr
PUBLIC GetLdtr
PUBLIC GetGdtBase
PUBLIC GetGdtLimit
PUBLIC GetIdtBase
PUBLIC GetIdtLimit
PUBLIC GetRflags
PUBLIC GetDr7
PUBLIC HvGetSegmentLimit
PUBLIC HvGetSegmentAr

HvVmxOn proc
    vmxon qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmxOn endp

HvVmxOff proc
    vmxoff
    pushfq
    pop rax
    ; VMXOFF reports VMfailInvalid/VMfailValid in CF/ZF. All existing C++
    ; cleanup callers historically ignore a return value, so a failed
    ; transition must not return to code that clears CR4 or frees VMX state.
    jc hvVmxOffFailed
    jz hvVmxOffFailed
    ret

hvVmxOffFailed:
    ; The caller is still in VMX root with its ordinary host stack. Keep
    ; interrupts disabled, preserve the first diagnostic snapshot while VMX
    ; state is still available, and never execute the caller's cleanup tail.
    cli
    ; Keep the raw VMXOFF flags in a lock-free, debugger-readable slot. The
    ; high bit marks the slot committed; compare-exchange preserves the first
    ; failure when more than one processor reaches this path.
    mov rdx, rax
    bts rdx, 3Fh
    xor eax, eax
    lock cmpxchg qword ptr [g_HvVmxOffFailureFlagsAsm], rdx
    xor ecx, ecx
    sub rsp, 28h
    call HvCaptureFatalSnapshotPreVmxoff
    add rsp, 28h
    sub rsp, 28h
    call MarkCurrentVcpuParked
    add rsp, 28h
    xor ecx, ecx
    sub rsp, 28h
    call HvFatalBugCheck
    add rsp, 28h
hvVmxOffFailedLoop:
    hlt
    jmp hvVmxOffFailedLoop
HvVmxOff endp

HvVmClear proc
    vmclear qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmClear endp

HvVmPtrSt proc
    vmptrst qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmPtrSt endp

HvVmPtrLd proc
    vmptrld qword ptr [rcx]
    pushfq
    pop rax
    ret
HvVmPtrLd endp

HvVmWrite proc
    ; masm uses the first VMWRITE operand for the field and the second
    ; for its value
    ; win64 passes the VMCS field in RCX and the value in RDX
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
    test al, 041h
    jnz vmreadFailed
    mov [rdx], r8
vmreadFailed:
    ret
HvVmReadChecked endp

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

end
