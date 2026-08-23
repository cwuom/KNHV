//
// Created by cwuom on 17 Feb 2026.
//


#pragma once
#include <ntddk.h>

// ==============================================================================
// Reference: Intel SDM Vol. 3C Appendix B, Intel SDM Vol. 4
// ==============================================================================

#define CR4_VMXE (1ULL << 13)
#define CR4_LA57 (1ULL << 12)
#define CR4_PCIDE (1ULL << 17)
#define CR4_CET  (1ULL << 23)

// MSR Index
#define MSR_IA32_FEATURE_CONTROL        0x0000003A
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048A
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048B
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS 0x0000048D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS     0x0000048F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS    0x00000490
#define MSR_IA32_VMX_PROCBASED_CTLS3    0x00000492
#define MSR_FS_BASE                     0xC0000100
#define MSR_GS_BASE                     0xC0000101
#define MSR_IA32_KERNEL_GS_BASE         0xC0000102
#define MSR_IA32_EFER                   0xC0000080
#define MSR_IA32_SYSENTER_CS            0x00000174
#define MSR_IA32_SYSENTER_ESP           0x00000175
#define MSR_IA32_SYSENTER_EIP           0x00000176
#define MSR_IA32_PAT                    0x00000277
#define MSR_IA32_DEBUGCTL               0x000001D9
#define MSR_IA32_XFD                    0x000001C4
#define MSR_IA32_XFD_ERR                0x000001C5
#define MSR_IA32_RTIT_OUTPUT_BASE       0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS  0x00000561
#define MSR_IA32_RTIT_CTL               0x00000570
#define MSR_IA32_RTIT_STATUS            0x00000571
#define MSR_IA32_RTIT_CR3_MATCH         0x00000572
#define MSR_IA32_RTIT_ADDR0_A           0x00000580
#define MSR_IA32_RTIT_ADDR3_B           0x00000587
// CET/XSAVES state is enabled only after the runtime capability contract has
// verified the paired CET VMCS controls and XSAVES support.
#define MSR_IA32_XSS                    0x00000DA0
#define MSR_IA32_U_CET                  0x000006A0
#define MSR_IA32_S_CET                  0x000006A2
#define MSR_IA32_PL0_SSP                0x000006A4
#define MSR_IA32_PL1_SSP                0x000006A5
#define MSR_IA32_PL2_SSP                0x000006A6
#define MSR_IA32_PL3_SSP                0x000006A7
#define MSR_IA32_INTERRUPT_SSP_TABLE    0x000006A8

// IA32_XSS state-component bits from the WDK/Intel XSTATE enumeration.
// CET_U contains IA32_U_CET and IA32_PL3_SSP; CET_S contains supervisor
// shadow-stack state. IPT is Intel Processor Trace state. These components are
// preserved by the complete compacted XSAVES/XRSTORS image used by the VM-exit
// frame.
#define IA32_XSS_IPT                        (1ULL << 8)
#define IA32_XSS_CET_U                      (1ULL << 11)
#define IA32_XSS_CET_S                      (1ULL << 12)
// The fixed XSAVES frame preserves the complete enumerated XSS state. Keep the
// IPT component in the guest selector contract as well; PT MSRs remain trapped
// so a guest cannot alter host tracing state through the VMX root path. CET_S
// remains outside the guest contract until all supervisor CET MSRs are virtualized.
#define IA32_XSS_GUEST_KNOWN_MASK            (IA32_XSS_IPT | IA32_XSS_CET_U)
#define IA32_XSS_VIRTUALIZABLE_MASK          IA32_XSS_GUEST_KNOWN_MASK

// Enable bits in IA32_{U,S}_CET. Other bits are state/configuration fields,
// not evidence that shadow-stack or IBT enforcement is currently running.
#define IA32_CET_SH_STK_EN                  (1ULL << 0)
#define IA32_CET_WR_SHSTK_EN                (1ULL << 1)
#define IA32_CET_ENDBR_EN                   (1ULL << 2)
#define IA32_CET_ENABLE_MASK                (IA32_CET_SH_STK_EN | \
                                             IA32_CET_WR_SHSTK_EN | \
                                             IA32_CET_ENDBR_EN)

// IA32_FEATURE_CONTROL bits and VMX capability bits.
#define IA32_FEATURE_CONTROL_LOCK                 (1ULL << 0)
#define IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX   (1ULL << 2)
#define VMX_BASIC_PHYSICAL_ADDRESS_32            (1ULL << 48)
#define VMX_BASIC_TRUE_CONTROLS                  (1ULL << 55)
#define VMX_BASIC_REVISION_MASK                  0x7FFFFFFFULL

// Mandatory-one masks from Intel's VMX capability MSRs. These bits are
// reserved/always-on and do not request a VM-exit by themselves.
#define VMX_PINBASED_MANDATORY_ON                0x00000016UL
#define VMX_PROCBASED_MANDATORY_ON               0x0401E172UL
#define VMX_EXIT_MANDATORY_ON                    0x00036DFFUL
#define VMX_ENTRY_MANDATORY_ON                   0x000011FFUL

// Primary/secondary VM-execution controls used by this driver.
#define PIN_BASED_EXTERNAL_INTERRUPT_EXITING    (1UL << 0)
#define PIN_BASED_NMI_EXITING                  (1UL << 3)
#define PIN_BASED_VIRTUAL_NMIS                 (1UL << 5)
#define PIN_BASED_PREEMPTION_TIMER             (1UL << 6)
#define PIN_BASED_POSTED_INTERRUPTS            (1UL << 7)
#define CPU_BASED_INTR_WINDOW_EXITING            (1UL << 2)
#define CPU_BASED_USE_TSC_OFFSETTING             (1UL << 3)
#define CPU_BASED_USE_MSR_BITMAPS                (1UL << 28)
#define CPU_BASED_ACTIVATE_TERTIARY_CONTROLS     (1UL << 17)
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS    (1UL << 31)
#define CPU_BASED_HLT_EXITING                   (1UL << 7)
#define CPU_BASED_INVLPG_EXITING                (1UL << 9)
#define CPU_BASED_MWAIT_EXITING                 (1UL << 10)
#define CPU_BASED_RDPMC_EXITING                 (1UL << 11)
#define CPU_BASED_RDTSC_EXITING                 (1UL << 12)
#define CPU_BASED_CR3_LOAD_EXITING              (1UL << 15)
#define CPU_BASED_CR3_STORE_EXITING             (1UL << 16)
#define CPU_BASED_CR8_LOAD_EXITING              (1UL << 19)
#define CPU_BASED_CR8_STORE_EXITING             (1UL << 20)
#define CPU_BASED_TPR_SHADOW                    (1UL << 21)
#define CPU_BASED_NMI_WINDOW_EXITING            (1UL << 22)
#define CPU_BASED_MOV_DR_EXITING                (1UL << 23)
#define CPU_BASED_UNCOND_IO_EXITING             (1UL << 24)
#define CPU_BASED_USE_IO_BITMAPS                (1UL << 25)
#define CPU_BASED_MONITOR_TRAP_FLAG             (1UL << 27)
#define CPU_BASED_MONITOR_EXITING               (1UL << 29)
#define CPU_BASED_PAUSE_EXITING                 (1UL << 30)
#define SECONDARY_ENABLE_RDTSCP                  (1UL << 3)
#define SECONDARY_ENABLE_INVPCID                 (1UL << 12)
#define SECONDARY_ENABLE_XSAVES                  (1UL << 20)
// CPUID.(0D,1).EAX feature bits. Bit 3 advertises the paired XSAVES and
// XRSTORS instructions; bit 4 is XFD, not a separate XRSTORS capability.
#define CPUID_D1_XSAVEOPT                        (1U << 0)
#define CPUID_D1_XSAVEC                          (1U << 1)
#define CPUID_D1_XGETBV1                         (1U << 2)
#define CPUID_D1_XSAVES                          (1U << 3)
#define CPUID_D1_XFD                             (1U << 4)
#define CPUID_7_EDX_FRED                         (1U << 17)
#define IA32_DEBUGCTL_LBR                        (1ULL << 0)
#define IA32_DEBUGCTL_BTF                        (1ULL << 1)
#define IA32_DEBUGCTL_BUS_LOCK_DETECT            (1ULL << 2)
#define IA32_DEBUGCTL_TR                         (1ULL << 6)
#define IA32_DEBUGCTL_BTS                        (1ULL << 7)
#define IA32_DEBUGCTL_BTINT                      (1ULL << 8)
#define IA32_DEBUGCTL_BTS_OFF_OS                 (1ULL << 9)
#define IA32_DEBUGCTL_BTS_OFF_USR                (1ULL << 10)
#define IA32_DEBUGCTL_FREEZE_LBRS_ON_PMI        (1ULL << 11)
#define IA32_DEBUGCTL_FREEZE_PERFMON_ON_PMI     (1ULL << 12)
#define IA32_DEBUGCTL_FREEZE_IN_SMM              (1ULL << 14)
#define IA32_DEBUGCTL_RTM_DEBUG                  (1ULL << 15)
#define IA32_DEBUGCTL_ARCHITECTURAL_MASK        \
    (IA32_DEBUGCTL_LBR | IA32_DEBUGCTL_BTF | IA32_DEBUGCTL_BUS_LOCK_DETECT | \
     IA32_DEBUGCTL_TR | IA32_DEBUGCTL_BTS | IA32_DEBUGCTL_BTINT | \
     IA32_DEBUGCTL_BTS_OFF_OS | IA32_DEBUGCTL_BTS_OFF_USR | \
     IA32_DEBUGCTL_FREEZE_LBRS_ON_PMI | \
     IA32_DEBUGCTL_FREEZE_PERFMON_ON_PMI | IA32_DEBUGCTL_FREEZE_IN_SMM | \
     IA32_DEBUGCTL_RTM_DEBUG)
#define EFER_SCE                                  (1ULL << 0)
#define EFER_LME                                  (1ULL << 8)
#define EFER_LMA                                  (1ULL << 10)
#define EFER_NXE                                  (1ULL << 11)
#define VM_EXIT_HOST_ADDRESS_SPACE_SIZE          (1UL << 9)
#define VM_EXIT_LOAD_CET_STATE                   (1UL << 28)
#define VM_EXIT_CLEAR_IA32_RTIT_CTL              (1UL << 25)
#define VM_ENTRY_IA32E_MODE_GUEST                (1UL << 9)
#define VM_EXIT_LOAD_HOST_EFER                   (1UL << 21)
#define VM_EXIT_LOAD_HOST_PAT                    (1UL << 19)
#define VM_EXIT_SAVE_DEBUG_CONTROLS              (1UL << 2)
#define VM_ENTRY_LOAD_GUEST_EFER                 (1UL << 15)
#define VM_ENTRY_LOAD_GUEST_PAT                  (1UL << 14)
#define VM_ENTRY_LOAD_CET_STATE                  (1UL << 20)
#define VM_ENTRY_LOAD_DEBUG_CONTROLS             (1UL << 2)
#define VM_ENTRY_INTR_INFO_VALID                 (1UL << 31)
#define VM_ENTRY_INTR_INFO_DELIVER_ERROR_CODE   (1UL << 11)
#define VM_ENTRY_INTR_TYPE_HARDWARE_EXCEPTION   (3UL << 8)
#define VM_EXIT_REASON_EXTERNAL_INTERRUPT       1
#define VM_EXIT_REASON_TRIPLE_FAULT              2
#define VM_EXIT_REASON_CPUID                    10
#define VM_EXIT_REASON_HLT                      12
#define VM_EXIT_REASON_INVLPG                   14
#define VM_EXIT_REASON_VMCALL                   18
#define VM_EXIT_REASON_CR_ACCESS                28
#define VM_EXIT_REASON_RDMSR                    31
#define VM_EXIT_REASON_WRMSR                    32
#define VM_EXIT_REASON_INVALID_GUEST_STATE      33
// VMX instructions are intentionally not virtualized (nested virtualization
// is outside this driver's scope).  If a non-root instruction reaches the
// exit handler, inject the architectural #UD rather than treating it as an
// unknown exit and resuming at the same RIP indefinitely.
#define VM_EXIT_REASON_VMCLEAR                  19
#define VM_EXIT_REASON_VMLAUNCH                 20
#define VM_EXIT_REASON_VMPTRLD                  21
#define VM_EXIT_REASON_VMPTRST                  22
#define VM_EXIT_REASON_VMREAD                   23
#define VM_EXIT_REASON_VMWRITE                  24
#define VM_EXIT_REASON_VMRESUME                 25
#define VM_EXIT_REASON_VMXOFF                   26
#define VM_EXIT_REASON_VMXON                    27
#define VM_EXIT_REASON_XSETBV                   55
#define VM_EXIT_REASON_XSAVES                   63
#define VM_EXIT_REASON_XRSTORS                  64

// VMCS Fields
enum VmcsField : ULONG {
    // 16-Bit Guest State
    GUEST_ES_SELECTOR = 0x800,
    GUEST_CS_SELECTOR = 0x802,
    GUEST_SS_SELECTOR = 0x804,
    GUEST_DS_SELECTOR = 0x806,
    GUEST_FS_SELECTOR = 0x808,
    GUEST_GS_SELECTOR = 0x80a,
    GUEST_LDTR_SELECTOR = 0x80c,
    GUEST_TR_SELECTOR = 0x80e,

    // 16-Bit Host State
    HOST_ES_SELECTOR = 0xc00,
    HOST_CS_SELECTOR = 0xc02,
    HOST_SS_SELECTOR = 0xc04,
    HOST_DS_SELECTOR = 0xc06,
    HOST_FS_SELECTOR = 0xc08,
    HOST_GS_SELECTOR = 0xc0a,
    HOST_TR_SELECTOR = 0xc0c,

    // 64-Bit Control
    CONTROL_IO_BITMAP_A_ADDRESS = 0x2000,
    CONTROL_IO_BITMAP_B_ADDRESS = 0x2002,
    CONTROL_MSR_BITMAP_ADDRESS = 0x2004,
    CONTROL_VMEXIT_MSR_STORE_ADDR = 0x2006,
    CONTROL_VMEXIT_MSR_LOAD_ADDR = 0x2008,
    CONTROL_VMENTRY_MSR_LOAD_ADDR = 0x200a,
    CONTROL_EXECUTIVE_VMCS_PTR = 0x200c,
    CONTROL_TSC_OFFSET = 0x2010,
    CONTROL_VIRTUAL_APIC_ADDRESS = 0x2012,
    // 64-bit control field used when secondary XSAVES is enabled.  A set bit
    // in this bitmap causes an XSAVES/XRSTORS VM-exit for the corresponding
    // IA32_XSS state component.
    CONTROL_XSS_EXITING_BITMAP = 0x202c,
    // 64-bit tertiary processor-based execution controls. The field is
    // meaningful only when primary bit 17 activates tertiary controls.
    CONTROL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x2034,

    // 64-Bit Guest State
    GUEST_VMCS_LINK_PTR = 0x2800,
    GUEST_DEBUGCTL = 0x2802,
    GUEST_PAT = 0x2804,
    GUEST_EFER = 0x2806,
    GUEST_PERF_GLOBAL_CTRL = 0x2808,
    GUEST_PDPTR0 = 0x280a,
    GUEST_PDPTR1 = 0x280c,
    GUEST_PDPTR2 = 0x280e,
    GUEST_PDPTR3 = 0x2810,

    // 64-Bit Host State
    HOST_PAT = 0x2c00,
    HOST_EFER = 0x2c02,
    HOST_PERF_GLOBAL_CTRL = 0x2c04,

    // 32-Bit Control
    CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS = 0x4000,
    CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x4002,
    CONTROL_EXCEPTION_BITMAP = 0x4004,
    CONTROL_PAGE_FAULT_ERROR_CODE_MASK = 0x4006,
    CONTROL_PAGE_FAULT_ERROR_CODE_MATCH = 0x4008,
    CONTROL_CR3_TARGET_COUNT = 0x400a,
    CONTROL_VM_EXIT_CONTROLS = 0x400c,
    CONTROL_VM_EXIT_MSR_STORE_COUNT = 0x400e,
    CONTROL_VM_EXIT_MSR_LOAD_COUNT = 0x4010,
    CONTROL_VM_ENTRY_CONTROLS = 0x4012,
    CONTROL_VM_ENTRY_MSR_LOAD_COUNT = 0x4014,
    CONTROL_VM_ENTRY_INTR_INFO_FIELD = 0x4016,
    CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE = 0x4018,
    CONTROL_VM_ENTRY_INSTRUCTION_LENGTH = 0x401a,
    CONTROL_TPR_THRESHOLD = 0x401c,
    CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x401e,

    // 32-Bit Read-Only
    VM_INSTRUCTION_ERROR = 0x4400,
    VM_EXIT_REASON = 0x4402,
    VM_EXIT_INTR_INFO = 0x4404,
    VM_EXIT_INTR_ERROR_CODE = 0x4406,
    VM_EXIT_IDT_VECTORING_INFO = 0x4408,
    VM_EXIT_IDT_VECTORING_ERROR_CODE = 0x440a,
    VM_EXIT_INSTRUCTION_LEN = 0x440c,
    VM_EXIT_INSTRUCTION_INFO = 0x440e,

    // 32-Bit Guest State
    GUEST_ES_LIMIT = 0x4800,
    GUEST_CS_LIMIT = 0x4802,
    GUEST_SS_LIMIT = 0x4804,
    GUEST_DS_LIMIT = 0x4806,
    GUEST_FS_LIMIT = 0x4808,
    GUEST_GS_LIMIT = 0x480a,
    GUEST_LDTR_LIMIT = 0x480c,
    GUEST_TR_LIMIT = 0x480e,
    GUEST_GDTR_LIMIT = 0x4810,
    GUEST_IDTR_LIMIT = 0x4812,
    GUEST_ES_AR_BYTES = 0x4814,
    GUEST_CS_AR_BYTES = 0x4816,
    GUEST_SS_AR_BYTES = 0x4818,
    GUEST_DS_AR_BYTES = 0x481a,
    GUEST_FS_AR_BYTES = 0x481c,
    GUEST_GS_AR_BYTES = 0x481e,
    GUEST_LDTR_AR_BYTES = 0x4820,
    GUEST_TR_AR_BYTES = 0x4822,
    GUEST_INTERRUPTIBILITY_INFO = 0x4824,
    GUEST_ACTIVITY_STATE = 0x4826,
    GUEST_SM_BASE = 0x4828,
    GUEST_SYSENTER_CS = 0x482a,

    // 32-Bit Host State
    HOST_IA32_SYSENTER_CS = 0x4c00,

    // Natural-Width Control
    CONTROL_CR0_GUEST_HOST_MASK = 0x6000,
    CONTROL_CR4_GUEST_HOST_MASK = 0x6002,
    CONTROL_CR0_READ_SHADOW = 0x6004,
    CONTROL_CR4_READ_SHADOW = 0x6006,
    CONTROL_CR3_TARGET_VALUE0 = 0x6008,
    CONTROL_CR3_TARGET_VALUE1 = 0x600a,
    CONTROL_CR3_TARGET_VALUE2 = 0x600c,
    CONTROL_CR3_TARGET_VALUE3 = 0x600e,

    // Natural-Width Read-Only
    EXIT_QUALIFICATION = 0x6400,
    IO_RCX = 0x6402,
    IO_RSI = 0x6404,
    IO_RDI = 0x6406,
    IO_RIP = 0x6408,
    GUEST_LINEAR_ADDRESS = 0x640a,

    // Natural-Width Guest State
    GUEST_CR0 = 0x6800,
    GUEST_CR3 = 0x6802,
    GUEST_CR4 = 0x6804,
    GUEST_ES_BASE = 0x6806,
    GUEST_CS_BASE = 0x6808,
    GUEST_SS_BASE = 0x680a,
    GUEST_DS_BASE = 0x680c,
    GUEST_FS_BASE = 0x680e,
    GUEST_GS_BASE = 0x6810,
    GUEST_LDTR_BASE = 0x6812,
    GUEST_TR_BASE = 0x6814,
    GUEST_GDTR_BASE = 0x6816,
    GUEST_IDTR_BASE = 0x6818,
    GUEST_DR7 = 0x681a,
    GUEST_RSP = 0x681c,
    GUEST_RIP = 0x681e,
    GUEST_RFLAGS = 0x6820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x6822,
    GUEST_SYSENTER_ESP = 0x6824,
    GUEST_SYSENTER_EIP = 0x6826,
    // CET state fields are valid only when the corresponding VM-entry/exit
    // CET controls are supported and enabled.  They are natural-width fields.
    GUEST_S_CET = 0x6828,
    GUEST_SSP = 0x682a,
    GUEST_INTR_SSP_TABLE = 0x682c,

    // Natural-Width Host State
    HOST_CR0 = 0x6c00,
    HOST_CR3 = 0x6c02,
    HOST_CR4 = 0x6c04,
    HOST_FS_BASE = 0x6c06,
    HOST_GS_BASE = 0x6c08,
    HOST_TR_BASE = 0x6c0a,
    HOST_GDTR_BASE = 0x6c0c,
    HOST_IDTR_BASE = 0x6c0e,
    HOST_IA32_SYSENTER_ESP = 0x6c10,
    HOST_IA32_SYSENTER_EIP = 0x6c12,
    HOST_RSP = 0x6c14,
    HOST_RIP = 0x6c16,
    HOST_S_CET = 0x6c18,
    HOST_SSP = 0x6c1a,
    HOST_INTR_SSP_TABLE = 0x6c1c
};
