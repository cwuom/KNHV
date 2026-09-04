; shared MASM declarations and architectural offsets
; keep this file free of procedures so every assembly module can include it

extern VmExitHandler:proc
extern PrepareHvCallback:proc
extern g_HvLaunchAssemblyEntered:dword
extern g_HvLaunchGuestEntered:dword
extern g_HvLaunchVmlaunchIssued:dword
extern g_HvLaunchVmlaunchReturned:dword
extern g_HvLaunchVmExitAsmReached:dword
extern g_HvVmExitDebugHold:dword
extern AbortHvLaunch:proc
extern HvTraceCurrentVcpuEvent:proc
extern HvFaultInjectedCurrent:proc
extern HvCaptureFatalSnapshotPreVmxoff:proc
extern HvClearCurrentVmcsAndRecord:proc
extern HvFailVmcsClear:proc
extern MarkCurrentVcpuLaunched:proc
extern MarkCurrentVcpuParked:proc
extern MarkCurrentVcpuTearingDown:proc
extern MarkCurrentVcpuStopped:proc
extern HandleVmResumeFailure:proc
extern HvFatalBugCheck:proc
extern HvHostExceptionBugCheck:proc
extern g_HvHostFaultRecord:byte
extern g_HvRootNmiCount:qword
extern g_LinearAddressBits:byte
extern g_CetVmcsEnabled:byte
extern g_XsavesEnabled:byte
extern g_XstateMode:byte
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
XSTATE_SAVE_FXSAVE equ 0
XSTATE_SAVE_XSAVE  equ 1
XSTATE_SAVE_XSAVES equ 2

; VMCS fields read by the VM-exit path.  The values are the architectural
; encodings from Intel SDM Vol. 3C, Table B-1.
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
CTX_NATIVE_IDT_BASE equ 01140h
CTX_NATIVE_IDT_LIMIT equ 01148h

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

; HvRestoreStateAndReturn stages state in a 100h-byte spill below the
; five-qword 64-bit IRETQ frame so it cannot overlap the active guest stack.
; The stack pointer itself remains the only address used after loading guest
; CR3, so the host VM-exit stack is never dereferenced there
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
RST_IDTR_LIMIT  equ 0C8h
RST_IDTR_BASE   equ 0CAh

; The thunk returns this value in RAX through the normal C++ call return
; address.  Bits used by the VMLAUNCH CF/ZF result are deliberately not relied
; on by this stub; the caller should compare the complete value first.
VMX_LAUNCH_SUCCESS_MAGIC equ 04C41554E43484544h
VMX_LAUNCH_NOT_VMX_MAGIC equ 0BAD0000000000001h
VMX_LAUNCH_MARKER_FAILURE_MAGIC equ 0BAD0000000000002h
HYPERVISOR_MAGIC         equ 013371337h
VMCALL_UNLOAD             equ 0DEADBEEFh

HV_TRACE_PRE_VMLAUNCH    equ 15
HV_TRACE_PRE_VMRESUME    equ 20
HV_TRACE_PRE_VMXOFF      equ 23
HV_TRACE_POST_VMXOFF     equ 24
HV_TRACE_VMRESUME_FAIL   equ 21
HV_TRACE_VMEXIT_HOST_READY equ 35
HV_TRACE_FATAL_SNAPSHOT_COMPLETE equ 29
HV_TRACE_FATAL_PARKED   equ 30
HV_FAULT_BEFORE_VMLAUNCH equ 8
HV_FAULT_VMLAUNCH_FAIL  equ 9
