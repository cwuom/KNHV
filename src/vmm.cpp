//
// Created by cwuom on 17 Feb 2026.
//

// ==============================================================================
// vmm.cpp
// Hypervisor Implementation
// ==============================================================================

#include "header/common.h"
#include <intrin.h>
#include <ntifs.h>
#include <ntdef.h>

#include "header/vmm.h"
#include "header/vmx.h"

extern "C" void StopHypervisor();
extern "C" PDRIVER_OBJECT g_HvDriverObject;

// ==============================================================================
// External Assembly Linking
// ==============================================================================
extern "C" {
    // defined in arch.asm
    u64 HvVmxOn(u64* Phys);
    void HvVmxOff();
    u64 HvVmClear(u64* Phys);
    u64 HvVmPtrLd(u64* Phys);
    u64 HvVmWrite(u64 Field, u64 Value);
    u64  HvVmRead(u64 Field);

    u64 HvLaunchGuest();
    void HvRestoreStateAndReturn(GuestContext* Ctx);
    void GuestStartThunk();
    void HvCall(u64 Magic, u64 Command, u64 Arg1, u64 Arg2);

    // entry point for vm-exit, used in vmcs setup
    void HvVmExitEntryPoint();

    // register helpers
    u16 GetCs(); u16 GetDs(); u16 GetEs(); u16 GetSs(); u16 GetFs(); u16 GetGs();
    u16 GetTr(); u16 GetLdtr();
    u64 GetGdtBase(); u16 GetGdtLimit(); u64 GetIdtBase(); u16 GetIdtLimit();
    u64 GetRflags();
    u32 HvGetSegmentLimit(u16 Selector);
    u32 HvGetSegmentAr(u16 Selector);

    // fixed-frame IPI launch wrapper in arch.asm and its C++ preparation
    // helpers.  VMLAUNCH never returns through compiler-generated state on a
    // successful entry; the wrapper owns that continuation explicitly.
    ULONG_PTR EnableHvCallback(ULONG_PTR Context);
    ULONG PrepareHvCallback(ULONG_PTR Context, void* GuestSp, void* GuestIp);
    void AbortHvLaunch(u64 Rflags);
    void MarkCurrentVcpuLaunched();
    void MarkCurrentVcpuParked();
}

// ==============================================================================
// Global State
// ==============================================================================
VcpuContext* g_VcpuData = nullptr;
u32 g_ProcessorCount = 0;
static volatile LONG g_HvLifecycle = 0;
static volatile LONG g_HvImagePinned = 0;
static u64 g_VmxBasic = 0;
// VMX host CR3 must always reference the kernel/system address space.  A
// KeIpiGenericCall callback may run while the interrupted thread belongs to a
// user process; capturing that process CR3 would leave the VM-exit stack and
// driver image unmapped under KPTI/25H2.
static u64 g_HostCr3 = 0;
static bool g_VmxRequires32BitPhysicalAddress = false;
extern "C" volatile u8 g_LinearAddressBits = 48;

// These flags are populated by InitializeVmxFeatureContract() before any
// processor enters VMX.  They are intentionally global and immutable for the
// lifetime of a hypervisor run: VMCS controls and the assembly save format
// must not change after VMLAUNCH.
static bool g_VmxFeatureContractInitialized = false;
static bool g_VmxFeatureContractValid = false;
extern "C" volatile u8 g_CetVmcsEnabled = 0;
extern "C" volatile u8 g_XsavesEnabled = 0;
// XSAVES/XRSTORS use this immutable compacted-mask contract. The guest's
// IA32_XSS value is kept separately, so a guest WRMSR never changes the frame
// layout used by the VM-exit assembly.
extern "C" volatile u64 g_XsavesMask = 0;
static u64 g_EnumeratedXssMask = 0;
static u64 g_SupportedXssMask = 0;
static u64 g_HostXssMask = 0;
static u32 g_XsaveStateSize = 0;
// Detailed per-CPU launch and ordinary VM-exit messages are opt-in. DbgPrint
// at IPI_LEVEL or with a kernel debugger attached can stop every processor;
// fatal and contract-failure messages remain unconditional.
extern "C" volatile LONG g_HvVerboseLogging = 0;
#define HV_VERBOSE_PRINT(...) \
    do { \
        if (g_HvVerboseLogging != 0) { \
            DbgPrint(__VA_ARGS__); \
        } \
    } while (0)
// Supervisor CET is not fully virtualized yet. Keep the guest CPUID contract
// honest until all S_CET/SSP transitions and exception paths are implemented.
static constexpr bool kGuestCetStateVirtualized = false;

static constexpr long kExitActionNone = 0;
static constexpr long kExitActionResume = 1;
static constexpr long kExitActionAbort = 2;
static constexpr long kExitActionHalt = 3;
static constexpr long kExitActionInject = 4;

// Bring-up/debug switch: only this logical processor executes VMXON/VMLAUNCH.
// Other processors return from the IPI callback without touching VMX state.
// Keep this enabled until a single CPU can repeatedly load/unload without
// dropping KDNET or bugchecking; then set kDebugSingleCpu to false.
static constexpr bool kDebugSingleCpu = true;
static constexpr u32  kDebugCpuIndex = 0;

static __forceinline bool ShouldLaunchOnThisProcessor(u32 id) {
    return !kDebugSingleCpu || id == kDebugCpuIndex;
}

static __forceinline u32 ExpectedLaunchProcessorCount() {
    return kDebugSingleCpu ? 1U : g_ProcessorCount;
}

static __forceinline u32 CurrentProcessorIndex();
static __forceinline u32 ControlMsr(u64 vmxBasic, u32 legacyMsr, u32 trueMsr);
static __forceinline bool IsCanonical(u64 value);

// CPUID.0D.1:EBX describes only the state selected by the current XCR0 and
// IA32_XSS values.  The VM-exit frame instead uses one immutable XSAVES mask,
// so calculate the compacted size from every component in that mask.
static bool ComputeXsaveAreaSize(u64 xcr0Mask, u64 xssMask,
                                 u64* enumeratedXss, u32* areaSize) {
    if (!enumeratedXss || !areaSize) return false;

    int regs[4] = {};
    __cpuid(regs, 0);
    if (static_cast<u32>(regs[0]) < 0xD) return false;

    __cpuidex(regs, 0xD, 0);
    const u64 supportedXcr0 = static_cast<u32>(regs[0]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    if ((xcr0Mask & ~supportedXcr0) != 0 ||
        (xcr0Mask & 0x3ULL) != 0x3ULL) {
        return false;
    }

    __cpuidex(regs, 0xD, 1);
    const u64 xssCapabilities =
        (static_cast<u32>(regs[2]) |
         (static_cast<u64>(static_cast<u32>(regs[3])) << 32)) &
        ~(1ULL << 63);
    *enumeratedXss = xssCapabilities;
    if ((xssMask & ~xssCapabilities) != 0) return false;

    u64 offset = 576;
    const u64 compactedMask = xcr0Mask | xssMask;
    for (u32 component = 2; component < 64; ++component) {
        const u64 bit = 1ULL << component;
        if ((compactedMask & bit) == 0) continue;

        __cpuidex(regs, 0xD, static_cast<int>(component));
        const u32 componentSize = static_cast<u32>(regs[0]);
        if (componentSize == 0) return false;
        if ((static_cast<u32>(regs[2]) & 0x2U) != 0) {
            offset = (offset + 63ULL) & ~63ULL;
        }
        offset += componentSize;
        if (offset > MAXULONG) return false;
    }

    *areaSize = static_cast<u32>(offset);
    return true;
}

static bool VmxControlAllows(u32 msr, u32 mask) {
    ULARGE_INTEGER value{};
    __try {
        value.QuadPart = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return (value.HighPart & mask) == mask;
}

static bool ReadMsrSafe(u32 msr, u64* value) {
    if (!value) return false;
    __try {
        *value = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static bool WriteMsrSafe(u32 msr, u64 value) {
    __try {
        __writemsr(msr, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

static bool EnsureFeatureControlForVmx() {
    u64 featureControl = 0;
    if (!ReadMsrSafe(MSR_IA32_FEATURE_CONTROL, &featureControl)) return false;
    const u64 required = IA32_FEATURE_CONTROL_LOCK |
                         IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX;
    if ((featureControl & IA32_FEATURE_CONTROL_LOCK) != 0) {
        return (featureControl & required) == required;
    }

    // Some firmware leaves this MSR unlocked until the first VMX owner. Set
    // only the two non-SMX VMX bits and the lock bit; preserve every other
    // firmware-selected option and verify the write before VMXON.
    const u64 provisioned = featureControl | required;
    if (!WriteMsrSafe(MSR_IA32_FEATURE_CONTROL, provisioned)) return false;
    u64 verified = 0;
    return ReadMsrSafe(MSR_IA32_FEATURE_CONTROL, &verified) &&
           (verified & required) == required;
}

static __forceinline bool IsIntelPtMsr(u32 msr) {
    // The Intel PT MSR block includes reserved holes. Intercepting the whole
    // architectural block is intentional: this build hides PT from the
    // guest and must not let a future PT MSR write alter host tracing state.
    return msr >= MSR_IA32_RTIT_OUTPUT_BASE && msr <= 0x58FU;
}

bool IsCETVmcsEnabled() {
    return g_CetVmcsEnabled;
}

bool IsXsavesEnabled() {
    return g_XsavesEnabled;
}

u32 GetXsaveStateSize() {
    return g_XsaveStateSize;
}

static bool IsGdtSelectorUsable(u64 gdtBase, u16 gdtLimit, u16 selector,
                                bool allowNull) {
    if (selector == 0) return allowNull;
    if ((selector & 0x4U) != 0 || (selector & 0xFFF8U) > gdtLimit) {
        return false;
    }
    if (!IsCanonical(gdtBase)) return false;
    return true;
}

bool InitializeVmxFeatureContract() {
    // Capability MSRs and CET/XSS state are sampled per load. Reusing a
    // previous run's result after unload could pair a new guest with stale
    // host state if Windows changed CET or tracing configuration meanwhile.
    if (g_VcpuData == nullptr) {
        g_VmxFeatureContractInitialized = false;
        g_VmxFeatureContractValid = false;
        g_CetVmcsEnabled = 0;
        g_XsavesEnabled = 0;
        g_XsavesMask = 0;
        g_EnumeratedXssMask = 0;
        g_SupportedXssMask = 0;
        g_HostXssMask = 0;
        g_XsaveStateSize = 0;
    }
    if (g_VmxFeatureContractInitialized) {
        return g_VmxFeatureContractValid;
    }
    g_VmxFeatureContractInitialized = true;
    g_VmxFeatureContractValid = false;
    g_CetVmcsEnabled = 0;
    g_XsavesEnabled = 0;
    g_XsavesMask = 0;
    g_EnumeratedXssMask = 0;
    g_SupportedXssMask = 0;
    g_HostXssMask = 0;
    g_XsaveStateSize = 0;

    int regs[4] = {};
    __cpuid(regs, 0);
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);
    if (maxBasicLeaf < 0xD) return false;

    const u64 currentCr4 = __readcr4();
    u64 hostXcr0 = 0;
    __try {
        hostXcr0 = _xgetbv(0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    __cpuidex(regs, 0xD, 0);
    const u64 supportedXcr0 = static_cast<u32>(regs[0]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    if ((supportedXcr0 & 0x3ULL) != 0x3ULL ||
        (hostXcr0 & ~supportedXcr0) != 0 ||
        (hostXcr0 & 0x3ULL) != 0x3ULL) {
        return false;
    }

    __cpuidex(regs, 0xD, 1);
    // Intel defines EAX[3] as the paired XSAVES/XRSTORS capability. EAX[4]
    // is XFD and must not be interpreted as an XRSTORS capability bit.
    const bool xsavesInstruction = (regs[0] & CPUID_D1_XSAVES) != 0;
    const bool xrstorsInstruction = xsavesInstruction;
    const bool xfdInstruction = (regs[0] & CPUID_D1_XFD) != 0;
    const u32 xsavesSize = static_cast<u32>(regs[1]);
    // XCOMP_BV bit 63 is reserved. Keep it out even if broken firmware reports
    // it in the XSS enumeration, because XRSTORS treats it as the compacted
    // format marker rather than a state-component selector.
    const u64 enumeratedXss = (static_cast<u32>(regs[2]) |
                              (static_cast<u64>(static_cast<u32>(regs[3])) << 32)) &
                             ~(1ULL << 63);
    g_EnumeratedXssMask = enumeratedXss;

    u64 hostXss = 0;
    const bool xssRead = ReadMsrSafe(MSR_IA32_XSS, &hostXss);
    if (xsavesInstruction && !xssRead) return false;
    if (xssRead && (hostXss & ~enumeratedXss) != 0) return false;

    DbgPrint("[HV] XSTATE contract: XSAVES=%u XRSTORS=%u XFD=%u D1.EBX=%lu "
             "XSS_ENUM=0x%llX HOST_XSS=0x%llX\n",
             xsavesInstruction ? 1U : 0U,
             xrstorsInstruction ? 1U : 0U,
             xfdInstruction ? 1U : 0U,
             static_cast<ULONG>(xsavesSize), enumeratedXss, hostXss);
    if (xsavesInstruction != xrstorsInstruction) return false;

    // Intel PT is part of the XSAVES image when XSS bit 8 is selected, but
    // this monitor does not program VMX PT load/clear controls. Refuse a host
    // that is actively tracing rather than running C++ on guest PT state.
    if ((hostXss & IA32_XSS_IPT) != 0) {
        u64 ptControl = 0;
        if (!ReadMsrSafe(MSR_IA32_RTIT_CTL, &ptControl) || ptControl != 0) {
            return 0;
        }
    }

    // The host selector is sampled independently from the immutable frame
    // contract. A guest may change its virtual selector without changing the
    // XSAVES layout used by the VM-exit assembly.
    g_HostXssMask = hostXss;
    g_SupportedXssMask = enumeratedXss & IA32_XSS_VIRTUALIZABLE_MASK;
    if ((hostXss & IA32_XSS_CET_S) != 0) return false;

if (xsavesInstruction && xssRead &&
    VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                      SECONDARY_ENABLE_XSAVES)) {
    // Late-launch rule: Windows has already booted with the live IA32_XSS
    // selector. Do not build the VM-exit XSAVES frame from components that
    // are merely CPUID-enumerated but not selected by the running OS.
    const u64 fixedXssMask = hostXss;
    if ((fixedXssMask & ~enumeratedXss) != 0 ||
        (fixedXssMask & ~IA32_XSS_VIRTUALIZABLE_MASK) != 0) {
        return false;
    }

    u64 computedXssCapabilities = 0;
    if (!ComputeXsaveAreaSize(hostXcr0, fixedXssMask,
                              &computedXssCapabilities,
                              &g_XsaveStateSize) ||
        computedXssCapabilities != enumeratedXss) {
        return false;
    }
    g_XsavesEnabled = 1;
    } else if (hostXss != 0) {
        // Ordinary XSAVE cannot preserve IA32_XSS-selected components.
        return false;
    }

    if (!g_XsavesEnabled) {
        __cpuidex(regs, 0xD, 0);
        g_XsaveStateSize = static_cast<u32>(regs[1]);
        g_SupportedXssMask = 0;
    }

    // Keep this value immutable for the lifetime of the VMX run. For a
    // late-launch monitor, the immutable compacted layout must match the
    // supervisor components selected by the already-running Windows kernel.
    // Expanding it to all CPUID-enumerated XSS bits changes the XSAVES/XRSTORS
    // contract after boot and can break exception/debugger paths.
    g_XsavesMask = g_XsavesEnabled ? g_HostXssMask : 0;
    // the guest selector must stay within the immutable frame mask. A guest
    // XSS bit that XSAVES does not capture would leak state across VM-exits
    g_SupportedXssMask &= g_XsavesMask;

    if (g_XsaveStateSize == 0 || g_XsaveStateSize > VMEXIT_XSAVE_MAX) {
        return false;
    }

    DbgPrint("[HV] XSTATE contract selected: XSAVES=%u frame=%lu "
             "HOST_XSS=0x%llX GUEST_XSS_MASK=0x%llX FIXED_XSS=0x%llX\n",
             g_XsavesEnabled ? 1U : 0U,
             static_cast<ULONG>(g_XsaveStateSize), g_HostXssMask,
             g_SupportedXssMask, g_XsavesMask);

    // CR4.CET is set on current Windows 11 builds even when supervisor CET
    // is inactive.  In that state VMX still requires the paired CET
    // entry/exit controls and valid zeroed VMCS CET fields.
    if ((currentCr4 & CR4_CET) != 0) {
        u64 vmxBasic = 0;
        if (!ReadMsrSafe(MSR_IA32_VMX_BASIC, &vmxBasic)) return false;
        if ((vmxBasic & VMX_BASIC_NO_HW_ERROR_CODE) == 0) return false;
        const u32 exitMsr = ControlMsr(vmxBasic,
                                       MSR_IA32_VMX_EXIT_CTLS,
                                       MSR_IA32_VMX_TRUE_EXIT_CTLS);
        const u32 entryMsr = ControlMsr(vmxBasic,
                                        MSR_IA32_VMX_ENTRY_CTLS,
                                        MSR_IA32_VMX_TRUE_ENTRY_CTLS);
        if (!VmxControlAllows(exitMsr, VM_EXIT_LOAD_CET_STATE) ||
            !VmxControlAllows(entryMsr, VM_ENTRY_LOAD_CET_STATE)) {
            return false;
        }
        g_CetVmcsEnabled = 1;
    }

    DbgPrint("[HV] VMX control contract: CET_VMCS=%u XSAVES=%u\n",
             g_CetVmcsEnabled ? 1U : 0U, g_XsavesEnabled ? 1U : 0U);

    g_VmxFeatureContractValid = true;
    return true;
}

// tags for memory allocation (avoid multi-char warnings by using integers)
constexpr u32 TAG_HV00 = 0x30305648; // 'HV00' little endian
constexpr u32 TAG_HVST = 0x54535648; // 'HVST' little endian

static __forceinline bool VmxOk(u64 rflags) {
    return ((rflags & 1ULL) == 0) && ((rflags & (1ULL << 6)) == 0);
}

static __forceinline bool VmWriteChecked(u64 field, u64 value) {
    const u64 flags = HvVmWrite(field, value);
    if (!VmxOk(flags) && g_VcpuData) {
        const u32 id = CurrentProcessorIndex();
        if (id < g_ProcessorCount) {
            InterlockedExchange(&g_VcpuData[id].VmcsWriteFailed, 1);
        }
    }
    return VmxOk(flags);
}

static __forceinline bool IsCanonical(u64 value) {
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

static __forceinline bool IsValidPatValue(u64 value) {
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

static __forceinline bool IsValidCr3(u64 value, u64 cr4 = __readcr4()) {
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

static __forceinline bool IsValidGuestState(const GuestContext* c) {
    if (!c || !IsCanonical(c->GuestRip) || !IsCanonical(c->GuestRsp)) {
        return false;
    }

    // The restore path writes a three-word IRET frame below RSP.  Reject
    // values that would underflow that frame or point at the low, unmapped
    // portion of the address space.  A kernel-mode Windows stack is always
    // well above this floor; this is intentionally conservative.
    if (c->GuestRsp < 0x200 || c->GuestRip < 0x10000) return false;

    // CR3 may carry a PCID in bits 11:0 when CR4.PCIDE is set (Windows uses
    // PCID/KPTI on current releases), so only reject a zero page-table base.
    if (!IsValidCr3(c->GuestCr3, c->GuestCr4)) {
        return false;
    }
    if (c->GuestCs == 0 || c->GuestSs == 0 ||
        (c->GuestCs & 3) != (c->GuestSs & 3)) {
        return false;
    }

    // This driver has no safe ring-3 teardown path.  Keep the direct restore
    // sequence restricted to a 64-bit ring-0 Windows context and reject
    // malformed control/MSR state before it can reach MOV CRx or WRMSR.
    if ((c->GuestCs & 3) != 0 || (c->GuestSs & 3) != 0 ||
        (c->GuestCr0 & 0x80000001ULL) != 0x80000001ULL ||
        (c->GuestCr4 & (1ULL << 5)) == 0 ||
        (c->GuestEfer & (1ULL << 10)) == 0 ||
        !IsCanonical(c->GuestFsBase) || !IsCanonical(c->GuestGsBase) ||
        !IsCanonical(c->GuestKernelGsBase) ||
        c->GuestSysenterCs > 0xFFFFULL ||
        !IsCanonical(c->GuestSysenterEsp) ||
        !IsCanonical(c->GuestSysenterEip) ||
        !IsValidPatValue(c->GuestPat)) {
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
    if ((c->Rflags & (1ULL << 1)) == 0 ||
        (c->Rflags & kRflagsReserved) != 0) {
        return false;
    }
    return true;
}

static __forceinline void RequestSafeExit(GuestContext* c) {
    if (c && (c->GuestCs & 3) == 0 && IsValidGuestState(c)) {
        c->AbortVm = 1;
    } else if (c) {
        c->HaltVm = 1;
    }
}

static __forceinline u32 CurrentProcessorIndex() {
    PROCESSOR_NUMBER number{};
    KeGetCurrentProcessorNumberEx(&number);
    return KeGetProcessorIndexFromNumber(&number);
}

// Called by the launch wrapper only after GuestStartThunk returned the
// success token from a real VMLAUNCH.  Publishing this state earlier makes a
// debugger or partial-start cleanup path mistake VMXON for a live guest.
extern "C" void MarkCurrentVcpuLaunched() {
    if (!g_VcpuData) return;
    const u32 id = CurrentProcessorIndex();
    if (id < g_ProcessorCount) {
        VcpuContext* vcpu = &g_VcpuData[id];
        InterlockedExchange(&vcpu->LaunchStage, 5);
        InterlockedExchange(&vcpu->State, VcpuLaunched);
    }
}

// Called from VMX-root fatal paths immediately before VMXOFF.  A parked CPU
// still executes the HLT loop in this image and may be interrupted by an IPI,
// so it cannot be reclaimed like a failed VMLAUNCH.
extern "C" void MarkCurrentVcpuParked() {
    if (!g_VcpuData) return;
    const u32 id = CurrentProcessorIndex();
    if (id < g_ProcessorCount) {
        InterlockedExchange(&g_VcpuData[id].LaunchStage, 7);
        InterlockedExchange(&g_VcpuData[id].State, VcpuParked);
    }
}
// ==============================================================================
// Helper Functions
// ==============================================================================

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

// ==============================================================================
// VM-Exit Handling
// ==============================================================================

static void InjectGuestException(GuestContext* c, u8 vector, bool hasErrorCode,
                                 u32 errorCode = 0) {
    if (!c) return;
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

static u64 AdjustControls64(u64 ctl, u32 msr) {
    const u64 value = __readmsr(msr);
    const u64 allowedOne = value >> 32;
    const u64 mandatoryOne = value & 0xFFFFFFFFULL;
    return (ctl & allowedOne) | mandatoryOne;
}

// handle hypervisor unload requests
bool HandleVmCall(GuestContext* Ctx) {
    // calling convention: rcx = magic, rdx = command
    if ((Ctx->GuestCs & 3U) == 0 &&
        Ctx->Rcx == HYPERVISOR_MAGIC && Ctx->Rdx == VMCALL_UNLOAD) {
        HV_VERBOSE_PRINT("[HV] unload VMCALL: cpu=%u rip=0x%llX rsp=0x%llX "
                         "rflags=0x%llX IF=%u cs=0x%llX ss=0x%llX\n",
                         CurrentProcessorIndex(), Ctx->GuestRip, Ctx->GuestRsp,
                         Ctx->Rflags, (Ctx->Rflags & (1ULL << 9)) != 0 ? 1U : 0U,
                         Ctx->GuestCs, Ctx->GuestSs);
        // VmExitHandler advances GUEST_RIP exactly once after this routine.
        // The assembly epilogue then VMXOFFs and returns through a real IRET
        // frame, allowing StopHvCallback's normal C++ epilogue to run.
        RequestSafeExit(Ctx);
        HV_VERBOSE_PRINT("[HV] unload VMCALL decision: cpu=%u abort=%llu halt=%llu "
                         "next_rip=0x%llX\n", CurrentProcessorIndex(), Ctx->AbortVm,
                         Ctx->HaltVm, Ctx->GuestRip + HvVmRead(VM_EXIT_INSTRUCTION_LEN));
        return true;
    }
    // The unload token is a ring-0 service call.  A guest CPL3 attempt must
    // not be allowed to select the native teardown path.
    InjectGuestException(Ctx, 6, false);
    return false;
}

bool HandleMsrRead(GuestContext* Ctx) {
    // RDMSR: reads the MSR specified by ECX into EDX:EAX
    u32 msrIndex = static_cast<u32>(Ctx->Rcx);

    // VMX entry/exit state owns these MSRs.  Read the guest copy rather than
    // exposing the host copy while executing in VMX root mode.
    if (msrIndex == MSR_FS_BASE) {
        const u64 value = HvVmRead(GUEST_FS_BASE);
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_GS_BASE) {
        const u64 value = HvVmRead(GUEST_GS_BASE);
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
        const u64 value = HvVmRead(GUEST_EFER);
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_PAT) {
        const u64 value = HvVmRead(GUEST_PAT);
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_CS) {
        const u64 value = HvVmRead(GUEST_SYSENTER_CS);
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_ESP) {
        const u64 value = HvVmRead(GUEST_SYSENTER_ESP);
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }
    if (msrIndex == MSR_IA32_SYSENTER_EIP) {
        const u64 value = HvVmRead(GUEST_SYSENTER_EIP);
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
        return true;
    }

    if (g_XsavesEnabled && msrIndex == MSR_IA32_XSS) {
        const u64 value = Ctx->GuestXss;
        Ctx->Rax = static_cast<u32>(value);
        Ctx->Rdx = static_cast<u32>(value >> 32);
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

    if (IsIntelPtMsr(msrIndex)) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }

    // These accesses should not reach the handler when XSAVES is active (the
    // bitmap leaves CET_U/PLx native).  Keep an explicit #GP fallback for a
    // capability mismatch rather than exposing VMX-root state.
    if (msrIndex == MSR_IA32_XSS || msrIndex == MSR_IA32_U_CET ||
        msrIndex == MSR_IA32_S_CET || msrIndex == MSR_IA32_PL0_SSP ||
        msrIndex == MSR_IA32_PL1_SSP || msrIndex == MSR_IA32_PL2_SSP ||
        msrIndex == MSR_IA32_PL3_SSP ||
        msrIndex == MSR_IA32_INTERRUPT_SSP_TABLE) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }

    InjectGuestException(Ctx, 13, true, 0);
    return false;
}

bool HandleMsrWrite(GuestContext* Ctx) {
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
        // Only architecturally defined EFER bits may be changed by the guest.
        const u64 oldValue = HvVmRead(GUEST_EFER);
        // LME/LMA are mode-transition bits and must remain consistent with
        // the IA-32e guest control.  Expose only SCE and NXE to the guest.
        const u64 newValue = (value.QuadPart & 0x801ULL) |
                             (oldValue & ~0x801ULL);
        if (!VmWriteChecked(GUEST_EFER, newValue)) {
            Ctx->HaltVm = 1;
            return false;
        }
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

    if (g_XsavesEnabled && msrIndex == MSR_IA32_XSS) {
        // The assembly frame always uses g_XsavesMask, so the guest selector
        // may change without changing the compacted memory layout. Reject only
        // components outside the negotiated virtual XSS contract.
        if ((value.QuadPart & ~g_SupportedXssMask) != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        Ctx->GuestXss = value.QuadPart;
        const u32 id = CurrentProcessorIndex();
        if (g_VcpuData && id < g_ProcessorCount) {
            g_VcpuData[id].GuestXss = value.QuadPart;
        }
        return true;
    }
    if (g_CetVmcsEnabled && msrIndex == MSR_IA32_S_CET) {
        // Supervisor CET is intentionally kept inactive. A non-zero S_CET
        // would require shadow-stack state that is not represented for every
        // privilege level by this monitor's VMCS contract.
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
        // There are no VMCS fields for PL1/PL2 in this fixed contract. Keep
        // the inactive supervisor CET state explicit and reject activation.
        if (value.QuadPart != 0) {
            InjectGuestException(Ctx, 13, true, 0);
            return false;
        }
        return true;
    }

    if (IsIntelPtMsr(msrIndex)) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }

    // The fallback path is used only when the bitmap was configured without
    // the corresponding state contract.  Never pass an intercepted CET MSR
    // through to VMX root.
    if (msrIndex == MSR_IA32_XSS || msrIndex == MSR_IA32_U_CET ||
        msrIndex == MSR_IA32_S_CET || msrIndex == MSR_IA32_PL0_SSP ||
        msrIndex == MSR_IA32_PL1_SSP || msrIndex == MSR_IA32_PL2_SSP ||
        msrIndex == MSR_IA32_PL3_SSP ||
        msrIndex == MSR_IA32_INTERRUPT_SSP_TABLE) {
        InjectGuestException(Ctx, 13, true, 0);
        return false;
    }

    InjectGuestException(Ctx, 13, true, 0);
    return false;
}

static bool ConfigureMsrBitmap(VcpuContext* vcpu) {
    if (!vcpu || !vcpu->MsrBitmapVirt) return false;

    // A one bit means "cause a VM-exit".  FS/GS/KERNEL_GS base, EFER, PAT and
    // SYSENTER CS/ESP/EIP are loaded from VMCS guest/host fields on every
    // VM-entry/VM-exit.  If the guest were
    // allowed to execute WRMSR natively, its write would update the hardware
    // MSR but not the VMCS copy; the next VM transition would then restore a
    // stale value (GS corruption is an especially common Windows failure).
    // Trap exactly these architecturally managed MSRs and leave all other
    // MSRs pass-through so normal Windows context switching is untouched.
    RtlZeroMemory(vcpu->MsrBitmapVirt, PAGE_SIZE);

    auto setBit = [&](u32 msr, bool write) -> bool {
        u32 base = 0;
        if (msr <= 0x1FFFU) {
            base = write ? 0x800U : 0x000U;
        } else if (msr >= 0xC0000000U && msr <= 0xC0001FFFU) {
            base = write ? 0xC00U : 0x400U;
            msr -= 0xC0000000U;
        } else {
            return false;
        }
        const u32 byteOffset = base + ((msr & 0x1FFFU) >> 3);
        const u8 bit = static_cast<u8>(1U << (msr & 7U));
        static_cast<u8*>(vcpu->MsrBitmapVirt)[byteOffset] |= bit;
        return true;
    };

    constexpr u32 baseManagedMsrs[] = {
        MSR_FS_BASE, MSR_GS_BASE, MSR_IA32_KERNEL_GS_BASE,
        MSR_IA32_EFER, MSR_IA32_PAT,
        MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP,
        MSR_IA32_SYSENTER_EIP,
    };
    for (u32 msr : baseManagedMsrs) {
        if (!setBit(msr, false) || !setBit(msr, true)) return false;
    }

    // Intel PT is not virtualized. Trap the complete RTIT MSR window so an
    // unadvertised or future PT register cannot change host tracing state.
    for (u32 msr = MSR_IA32_RTIT_OUTPUT_BASE; msr <= 0x58FU; ++msr) {
        if (!setBit(msr, false) || !setBit(msr, true)) return false;
    }

    // IA32_XSS is the selector consumed by XSAVES and has no VMCS field, so
    // it is always trapped and kept per virtual CPU.  CET_U and PL3_SSP are
    // part of the compacted XSTATE image and can pass through only when that
    // image is active. Supervisor CET MSRs stay trapped because this build
    // requires S_CET, PL0..PL2 and the interrupt SSP table to remain zero.
    if (!setBit(MSR_IA32_XSS, false) || !setBit(MSR_IA32_XSS, true)) {
        return false;
    }
    const bool cetUserStateSupported =
        g_XsavesEnabled && (g_SupportedXssMask & IA32_XSS_CET_U) != 0;
    if (!cetUserStateSupported) {
        constexpr u32 cetUserMsrs[] = {
            MSR_IA32_U_CET, MSR_IA32_PL3_SSP,
        };
        for (u32 msr : cetUserMsrs) {
            if (!setBit(msr, false) || !setBit(msr, true)) return false;
        }
    }
    constexpr u32 cetSupervisorMsrs[] = {
        MSR_IA32_S_CET, MSR_IA32_PL0_SSP, MSR_IA32_PL1_SSP,
        MSR_IA32_PL2_SSP, MSR_IA32_INTERRUPT_SSP_TABLE,
    };
    for (u32 msr : cetSupervisorMsrs) {
        if (!setBit(msr, false) || !setBit(msr, true)) return false;
    }
    return true;
}

static __forceinline u32 ControlMsr(u64 vmxBasic, u32 legacyMsr, u32 trueMsr) {
    return (vmxBasic & VMX_BASIC_TRUE_CONTROLS) ? trueMsr : legacyMsr;
}

static __forceinline u32 ControlMandatoryOn(u32 msr) {
    return static_cast<u32>(__readmsr(msr));
}

static __forceinline u64 GetGpr(const GuestContext* c, u8 reg) {
    switch (reg) {
        case 0: return c->Rax; case 1: return c->Rcx; case 2: return c->Rdx; case 3: return c->Rbx;
        case 4: return c->GuestRsp; case 5: return c->Rbp; case 6: return c->Rsi; case 7: return c->Rdi;
        case 8: return c->R8;  case 9: return c->R9;  case 10: return c->R10; case 11: return c->R11;
        case 12: return c->R12; case 13: return c->R13; case 14: return c->R14; case 15: return c->R15;
        default: return 0;
    }
}

static __forceinline bool SetGpr(GuestContext* c, u8 reg, u64 v) {
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

static bool HandleCrAccess(GuestContext* c) {
    const u64 qual = HvVmRead(EXIT_QUALIFICATION);
    const u8 crNum = static_cast<u8>(qual & 0xF);
    const u8 accessType = static_cast<u8>((qual >> 4) & 0x3);
    const u8 gpr = static_cast<u8>((qual >> 8) & 0xF);

    if (accessType == 0) {
        const u64 value = GetGpr(c, gpr);
        if (crNum == 0) {
            const u64 newCr0 = AdjustCr0(value);
            if (!VmWriteChecked(GUEST_CR0, newCr0) ||
                !VmWriteChecked(CONTROL_CR0_READ_SHADOW, newCr0)) {
                c->HaltVm = 1;
                return 0;
            }
            return true;
        }
        if (crNum == 4) {
            if ((value & CR4_CET) != 0 && !g_CetVmcsEnabled) {
                HV_VERBOSE_PRINT("[HV] CPU %u rejected guest CR4.CET without VMCS "
                                 "CET contract: value=0x%llX\n",
                                 CurrentProcessorIndex(), value);
                InjectGuestException(c, 13, true, 0);
                return 0;
            }
            const u64 requestedCr4 = AdjustCr4(value | CR4_VMXE);
            const u64 currentCr3 = HvVmRead(GUEST_CR3);
            if (!IsValidCr3(currentCr3, requestedCr4)) {
                HV_VERBOSE_PRINT("[HV] CPU %u rejected guest CR4 transition: "
                                 "cr4=0x%llX cr3=0x%llX\n",
                                 CurrentProcessorIndex(), requestedCr4, currentCr3);
                InjectGuestException(c, 13, true, 0);
                return false;
            }
            const u64 actualCr4 = requestedCr4;
            if (!VmWriteChecked(GUEST_CR4, actualCr4) ||
                !VmWriteChecked(CONTROL_CR4_READ_SHADOW, (value & ~CR4_VMXE))) {
                c->HaltVm = 1;
                return false;
            }
            return true;
        }
        if (crNum == 3) {
            if (!IsValidCr3(value, HvVmRead(GUEST_CR4)) ||
                !VmWriteChecked(GUEST_CR3, value)) {
                InjectGuestException(c, 13, true, 0);
                return false;
            }
            c->GuestCr3 = value;
            return true;
        }
        InjectGuestException(c, 6, false);
        return false;
    }
    if (accessType == 1) {
        if (crNum == 0) {
            if (!SetGpr(c, gpr, HvVmRead(GUEST_CR0))) c->HaltVm = 1;
            return c->HaltVm == 0;
        }
        if (crNum == 4) {
            if (!SetGpr(c, gpr, HvVmRead(CONTROL_CR4_READ_SHADOW))) c->HaltVm = 1;
            return c->HaltVm == 0;
        }
        if (crNum == 3) {
            if (!SetGpr(c, gpr, HvVmRead(GUEST_CR3))) c->HaltVm = 1;
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
// guest/host state.  The VM-exit assembly therefore uses the live XCR0 mask
// while saving the guest frame.  Changing that mask from the non-root side
// would make the subsequent C++ XSAVE/XRSTOR operate on a different layout
// (and can overwrite the fixed GPR area).  We intentionally support only the
// no-op form used by firmware/OS probes: an XSETBV request for XCR0 that is
// identical to the root mask captured at launch.  Invalid/different requests
// receive the architectural #GP(0) without executing XSETBV in VMX root.
static bool HandleXsetbv(GuestContext* c, const VcpuContext* vcpu) {
    if (!c || !vcpu) return false;

    // If the live mask has already diverged, the assembly prologue could not
    // have been given a host-compatible XSAVE layout.  Do not attempt another
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
        HV_VERBOSE_PRINT("[HV] XCR0 diverged on processor %u (live 0x%llX host 0x%llX)\n",
                         CurrentProcessorIndex(), liveXcr0, vcpu->HostXcr0);
        c->HaltVm = 1;
        return false;
    }

    const u32 xcrIndex = static_cast<u32>(c->Rcx);
    const u64 requested = (static_cast<u64>(static_cast<u32>(c->Rdx)) << 32) |
                          static_cast<u32>(c->Rax);
    if (xcrIndex != 0 || requested != vcpu->HostXcr0 ||
        (requested & 0x3ULL) != 0x3ULL) {
        // #GP is an error-code exception; XSETBV reports #GP(0).  Mark the
        // VM-entry injection accordingly so the guest exception frame has the
        // architectural fifth word and does not corrupt the guest stack.
        InjectGuestException(c, 13, true, 0);
        return false;
    }

    // Reject bits the processor does not enumerate in CPUID.(EAX=0Dh,ECX=0).
    // This is redundant for the equality check above on a healthy launch, but
    // keeps the VM-entry contract fail-closed if a future caller changes the
    // captured host mask without updating the capability gate.
    int regs[4] = {};
    __cpuidex(regs, 0xD, 0);
    const u64 supported = static_cast<u32>(regs[0]) |
                          (static_cast<u64>(static_cast<u32>(regs[3])) << 32);
    if ((requested & ~supported) != 0) {
        InjectGuestException(c, 13, true, 0);
        return false;
    }
    return true;
}

extern "C" void VmExitHandler(GuestContext* Ctx) {
    if (!Ctx) return;
    const u64 ExitReason = HvVmRead(VM_EXIT_REASON) & 0xFFFF;
    const u64 ExitLen    = HvVmRead(VM_EXIT_INSTRUCTION_LEN);
    const u32 cpuId = CurrentProcessorIndex();
    if (!g_VcpuData || cpuId >= g_ProcessorCount) {
        HV_VERBOSE_PRINT("[HV] VM-exit without a valid VCPU: cpu=%u reason=%llu\n",
                         cpuId, ExitReason);
        Ctx->HaltVm = 1;
        return;
    }
    VcpuContext* vcpu = &g_VcpuData[cpuId];
    const long exitCount = InterlockedIncrement(&vcpu->VmExitCount);
    // Keep the first exits verbose and retain power-of-two checkpoints so a
    // long-running guest still leaves a bounded, useful trace in KD.
    const bool logExit = g_HvVerboseLogging != 0 &&
                         (exitCount <= 16 ||
                          (exitCount > 16 &&
                           (exitCount & (exitCount - 1)) == 0));

    // A VM-entry interruption field is consumed only once by hardware. Clear
    // it at the start of every exit so a previous injected #GP/#UD cannot be
    // accidentally delivered again after the guest resumes.
    if (!VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0) ||
        !VmWriteChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, 0)) {
        HV_VERBOSE_PRINT("[HV] VM-entry injection state clear failed: cpu=%u "
                         "reason=%llu\n", cpuId, ExitReason);
        Ctx->HaltVm = 1;
        return;
    }

    // synchronize context
    Ctx->GuestRip = HvVmRead(GUEST_RIP);
    Ctx->GuestRsp = HvVmRead(GUEST_RSP);
    Ctx->Rflags   = HvVmRead(GUEST_RFLAGS);
    Ctx->GuestCs  = HvVmRead(GUEST_CS_SELECTOR);
    Ctx->GuestSs  = HvVmRead(GUEST_SS_SELECTOR);
    Ctx->GuestCr3 = HvVmRead(GUEST_CR3);
    Ctx->GuestCr4 = HvVmRead(GUEST_CR4);
    Ctx->GuestCr0 = HvVmRead(GUEST_CR0);
    Ctx->GuestFsBase = HvVmRead(GUEST_FS_BASE);
    Ctx->GuestGsBase = HvVmRead(GUEST_GS_BASE);
    Ctx->GuestEfer = HvVmRead(GUEST_EFER);
    Ctx->GuestPat = HvVmRead(GUEST_PAT);
    Ctx->GuestSysenterCs = HvVmRead(GUEST_SYSENTER_CS);
    Ctx->GuestSysenterEsp = HvVmRead(GUEST_SYSENTER_ESP);
    Ctx->GuestSysenterEip = HvVmRead(GUEST_SYSENTER_EIP);
    vcpu->LastExitReason = static_cast<long>(ExitReason);
    vcpu->LastExitQualification = HvVmRead(EXIT_QUALIFICATION);
    vcpu->LastGuestRip = Ctx->GuestRip;
    vcpu->LastGuestRsp = Ctx->GuestRsp;
    vcpu->LastRflags = Ctx->Rflags;
    if (g_CetVmcsEnabled) {
        Ctx->GuestSCet = HvVmRead(GUEST_S_CET);
        Ctx->GuestSsp = HvVmRead(GUEST_SSP);
        Ctx->GuestInterruptSspTable = HvVmRead(GUEST_INTR_SSP_TABLE);
    }
    if (logExit) {
        HV_VERBOSE_PRINT("[HV] VM-exit cpu=%u count=%ld reason=%llu len=%llu "
                         "rip=0x%llX rsp=0x%llX rflags=0x%llX qual=0x%llX\n",
                         cpuId, exitCount, ExitReason, ExitLen, Ctx->GuestRip,
                         Ctx->GuestRsp, Ctx->Rflags, HvVmRead(EXIT_QUALIFICATION));
    }
    // IA32_KERNEL_GS_BASE is not represented in the VMCS.  The VM-exit
    // assembly stub snapshots the guest value before restoring the host
    // per-CPU value; copy that snapshot into the teardown context so the
    // validity checks and VMXOFF/IRET path can restore it exactly.
    // (The field is already populated at CTX_GUEST_KGS by arch.asm.)

    // SWAPGS does not cause a VM-exit and IA32_KERNEL_GS_BASE is not loaded
    // from VMCS on VM-entry/exit. Compare the live KGS captured by the assembly
    // stub with the software pair from the previous entry. An odd SWAPGS leaves
    // KGS equal to the previous guest GS; repair the VMCS GS field before
    // resuming. WRMSR to either base is trapped and updates this same pair.
    if (g_XsavesEnabled) {
        if ((Ctx->GuestXss & ~g_SupportedXssMask) != 0) {
            HV_VERBOSE_PRINT("[HV] Guest IA32_XSS contains unsupported bits: 0x%llX\n",
                             Ctx->GuestXss);
            Ctx->HaltVm = 1;
            return;
        }
        vcpu->GuestXcr0 = Ctx->GuestXcr0;
        vcpu->GuestXss = Ctx->GuestXss;
    }
    const u64 observedKgs = Ctx->GuestKernelGsBase;
    const u64 expectedGs = vcpu->GuestGsBase;
    const u64 expectedKgs = vcpu->GuestKernelGsBase;
    if (observedKgs == expectedKgs) {
        // Normal state (or an even SWAPGS sequence).  Keep the VMCS guest GS
        // value that was read above: a trapped WRMSR GS_BASE may have changed
        // it since the last exit, and overwriting it with expectedGs here
        // would silently discard that guest write.
        Ctx->GuestKernelGsBase = observedKgs;
    } else if (observedKgs == expectedGs) {
        // An odd SWAPGS exchanges the two architectural bases without a VM
        // exit.  Repair the VMCS guest GS field before VMENTRY and retain the
        // exchanged pair as the guest's new state.
        Ctx->GuestGsBase = expectedKgs;
        Ctx->GuestKernelGsBase = observedKgs;
        if (!VmWriteChecked(GUEST_GS_BASE, expectedKgs)) {
            Ctx->HaltVm = 1;
            return;
        }
    } else {
        // A value outside the tracked pair means an untrapped MSR write or
        // corrupted host state. Re-entering with a guessed GS base can
        // corrupt KPCR/IRQL state, so fail closed and park this CPU.
        HV_VERBOSE_PRINT("[HV] Untracked KERNEL_GS_BASE 0x%llX (expected 0x%llX/0x%llX)\n",
                         observedKgs, expectedKgs, expectedGs);
        Ctx->HaltVm = 1;
        return;
    }
    vcpu->GuestGsBase = Ctx->GuestGsBase;
    vcpu->GuestKernelGsBase = Ctx->GuestKernelGsBase;

    bool AdvanceRip = true;

    switch (ExitReason) {
        case VM_EXIT_REASON_CPUID: // CPUID
        {
            if (Ctx->Rax == 0x13371337) {
                HV_VERBOSE_PRINT("[HV] Magic CPUID Intercepted on Core %d!\n",
                                 KeGetCurrentProcessorNumber());
                Ctx->Rax = 0x13371337;
                Ctx->Rbx = 0xDEADC0DE; // dead code
                Ctx->Rcx = 0xC0FFEE;   // coffee
                Ctx->Rdx = 0x48564856;
            }
            else {
                int regs[4] = {};
                const u32 leaf = static_cast<u32>(Ctx->Rax);
                const u32 subleaf = static_cast<u32>(Ctx->Rcx);

                // CPUID leaves outside the advertised basic/extended ranges
                // are architecturally treated as unsupported.  Returning
                // zeros is deterministic and avoids exposing host-specific
                // undefined values through the monitor.
                int maxRegs[4] = {};
                __cpuidex(maxRegs, 0, 0);
                const u32 maxBasicLeaf = static_cast<u32>(maxRegs[0]);
                __cpuidex(maxRegs, 0x80000000, 0);
                const u32 maxExtendedLeaf = static_cast<u32>(maxRegs[0]);
                const bool basicLeaf = leaf <= maxBasicLeaf;
                const bool extendedLeaf = leaf >= 0x80000000U &&
                                          leaf <= maxExtendedLeaf;
                // Hypervisor leaves are deliberately not implemented by this
                // non-nested monitor.  Do not leak a host hypervisor ABI.
                const bool hypervisorLeaf = leaf >= 0x40000000U &&
                                            leaf <= 0x4FFFFFFFU;
                if ((basicLeaf || extendedLeaf) && !hypervisorLeaf) {
                    __cpuidex(regs, static_cast<int>(leaf),
                              static_cast<int>(subleaf));

                    if (leaf == 1) {
                        // Do not advertise VMX to a guest: nested
                        // virtualization is intentionally unsupported.
                        regs[2] &= ~(1 << 5);
                    } else if (leaf == 7 && subleaf == 0) {
                        // Intel PT and supervisor CET are host-only until the
                        // complete supervisor CET transition contract exists.
                        regs[1] &= ~(1 << 25);  // Intel PT
                        const bool cetGuestSupported =
                            kGuestCetStateVirtualized && g_CetVmcsEnabled &&
                            g_XsavesEnabled &&
                            (g_SupportedXssMask & IA32_XSS_CET_U) != 0;
                        if (!cetGuestSupported) {
                            regs[2] &= ~(1 << 7);   // CET_SS
                            regs[3] &= ~(1 << 20);  // CET_IBT
                        }
                    } else if (leaf == 0x14) {
                        // Leaf 0x14 enumerates Intel Processor Trace. Returning
                        // zero keeps PT consistently hidden with CPUID.7.
                        RtlZeroMemory(regs, sizeof(regs));
                    } else if (leaf == 0xD && subleaf == 0) {
                        // XSETBV is intentionally fixed to the host mask. Do
                        // not advertise AVX-512/AMX components that the guest
                        // cannot enable without a dynamic XSAVE contract.
                        const u64 virtualXcr0 = vcpu->HostXcr0;
                        regs[0] &= static_cast<int>(virtualXcr0);
                        regs[3] &= static_cast<int>(virtualXcr0 >> 32);
                    } else if (leaf == 0xD && subleaf == 1) {
                        if (!g_XsavesEnabled) {
                            // Do not advertise XSAVES/XRSTORS when the
                            // compacted supervisor-state path is unavailable.
                            regs[0] &= ~(1 << 3);  // XSAVES
                            regs[0] &= ~(1 << 4);  // XRSTORS
                            regs[2] &= static_cast<int>(0xFFFFFFFFULL &
                                                        static_cast<u32>(g_SupportedXssMask));
                            regs[3] &= static_cast<int>(g_SupportedXssMask >> 32);
                        }
                        // IA32_XSS is a guest selector, so expose only the
                        // components the current virtual CPU may select. The
                        // assembly frame uses g_XsavesMask and is deliberately
                        // independent from this value.
                        regs[2] &= static_cast<int>(g_SupportedXssMask);
                        regs[3] &= static_cast<int>(g_SupportedXssMask >> 32);
                    } else if (leaf == 0xD && subleaf >= 2 && subleaf < 64) {
                        const u64 component = 1ULL << subleaf;
                        const bool xcr0Component =
                            (vcpu->HostXcr0 & component) != 0;
                        const bool xssComponent =
                            (g_SupportedXssMask & component) != 0;
                        if (!xcr0Component && !xssComponent) {
                            RtlZeroMemory(regs, sizeof(regs));
                        } else if ((subleaf == 11 || subleaf == 12) &&
                                   !kGuestCetStateVirtualized) {
                            // CET supervisor fields are preserved in the
                            // fixed frame but are not exposed as guest
                            // capabilities until their MSR contract is done.
                            RtlZeroMemory(regs, sizeof(regs));
                        } else if (subleaf == 8 &&
                                   (g_SupportedXssMask & IA32_XSS_IPT) == 0) {
                            RtlZeroMemory(regs, sizeof(regs));
                        }
                    }
                } else {
                    RtlZeroMemory(regs, sizeof(regs));
                }

                // CPUID writes four 32-bit registers and zero-extends them
                // in 64-bit mode.  `regs` is an `int[4]`; assigning directly
                // would sign-extend outputs whose high bit is set and leak
                // non-architectural ones in the upper halves of GPRs.
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
            if (logExit) {
            HV_VERBOSE_PRINT("[HV] CR access cpu=%u count=%ld qual=0x%llX "
                             "cr3=0x%llX cr4=0x%llX\n", cpuId, exitCount,
                             HvVmRead(EXIT_QUALIFICATION), HvVmRead(GUEST_CR3),
                             HvVmRead(GUEST_CR4));
            }
            AdvanceRip = HandleCrAccess(Ctx);
            break;

        case VM_EXIT_REASON_VMCLEAR:
        case VM_EXIT_REASON_VMLAUNCH:
        case VM_EXIT_REASON_VMPTRLD:
        case VM_EXIT_REASON_VMPTRST:
        case VM_EXIT_REASON_VMREAD:
        case VM_EXIT_REASON_VMWRITE:
        case VM_EXIT_REASON_VMRESUME:
        case VM_EXIT_REASON_VMXOFF:
        case VM_EXIT_REASON_VMXON:
            // Nested virtualization is deliberately unsupported.  VMX
            // instructions executed in non-root are architecturally #UD for
            // this monitor; inject that fault at the original RIP rather
            // than parking a processor on an attacker-controlled instruction.
            InjectGuestException(Ctx, 6, false);
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_XSETBV:
            AdvanceRip = HandleXsetbv(Ctx, vcpu);
            break;

        case VM_EXIT_REASON_XSAVES:
        case VM_EXIT_REASON_XRSTORS:
            // The fixed XSAVE mask makes the guest state recoverable even if a
            // future CPU reports this instruction unexpectedly. Leave VMX and
            // execute the instruction natively rather than parking a CPU.
            HV_VERBOSE_PRINT("[HV] Unexpected XSAVES/XRSTORS VM-exit cpu=%u reason=%llu\n",
                             cpuId, ExitReason);
            RequestSafeExit(Ctx);
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_EXTERNAL_INTERRUPT: // external interrupt
            // SetupVmcs rejects every pin-based interrupt-exit control.  If
            // this reason is nevertheless observed (for example after a
            // firmware/VMX capability mismatch), leave VMX and let the host
            // execute the interrupted context natively.
            RequestSafeExit(Ctx);
            AdvanceRip = false;
            break;

        case VM_EXIT_REASON_TRIPLE_FAULT: // triple fault
        case VM_EXIT_REASON_INVALID_GUEST_STATE: // invalid guest state
            // There is no architectural continuation for these exits.  Park
            // the processor after VMXOFF rather than re-entering an invalid
            // guest state and creating another reset/triple-fault cascade.
            HV_VERBOSE_PRINT("[HV] FATAL VM-exit cpu=%u count=%ld reason=%llu "
                             "rip=0x%llX rsp=0x%llX cr3=0x%llX cr4=0x%llX\n",
                             cpuId, exitCount, ExitReason, Ctx->GuestRip,
                             Ctx->GuestRsp, Ctx->GuestCr3, Ctx->GuestCr4);
            Ctx->HaltVm = 1;
            AdvanceRip = false;
            break;

        case 0: // exception or NMI: no exception bitmap is enabled by default.
        default:
            // These exits are not requested by our control bitmap.  There is
            // no generic emulation is available, so leave VMX and execute the
            // interrupted kernel context natively instead of looping in VMX.
            HV_VERBOSE_PRINT("[HV] UNSUPPORTED VM-exit cpu=%u count=%ld reason=%llu "
                             "rip=0x%llX rsp=0x%llX qual=0x%llX\n",
                             cpuId, exitCount, ExitReason, Ctx->GuestRip,
                             Ctx->GuestRsp, HvVmRead(EXIT_QUALIFICATION));
            RequestSafeExit(Ctx);
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
            Ctx->HaltVm = 1;
            vcpu->LastExitAction = kExitActionHalt;
            return;
        }
        Ctx->GuestRip = nextRip;
        if (!VmWriteChecked(GUEST_RIP, nextRip)) {
            // A failed VMWRITE leaves the VMCS/software RIP pair
            // inconsistent.  Do not attempt VMRESUME with partially updated
            // guest state; the assembly epilogue will take the park path.
            Ctx->HaltVm = 1;
            vcpu->LastExitAction = kExitActionHalt;
            return;
        }
    }

    const u32 id = CurrentProcessorIndex();
    if (g_VcpuData && id < g_ProcessorCount &&
        g_VcpuData[id].VmcsWriteFailed != 0) {
        // A failed VMWRITE means the VMCS no longer matches the software
        // context.  Never attempt VMRESUME with partially updated state.
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
    if (!Ctx->HaltVm && !Ctx->AbortVm) {
        InterlockedIncrement(&vcpu->VmResumeAttempts);
    }
}

// ==============================================================================
// VMCS Setup
// ==============================================================================

// extract the 64-bit base address from a 16-byte tss descriptor
u64 GetTssBase(const u64 GdtBase, const u16 GdtLimit, const u16 Selector) {
    const u64 offset = Selector & 0xFFF8U;
    if (offset == 0 || offset > GdtLimit || GdtLimit - offset < 15U ||
        !IsCanonical(GdtBase) || !IsCanonical(GdtBase + offset)) {
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

    return base;
}

// initialize the vmcs for a single virtual cpu
bool SetupVmcs(const VcpuContext* Vcpu, void* GuestSp, void* GuestIp) {
    if (!Vcpu) return false;
    VcpuContext* mutableVcpu = const_cast<VcpuContext*>(Vcpu);
    InterlockedExchange(&mutableVcpu->VmcsWriteFailed, 0);
    const u32 cpuId = CurrentProcessorIndex();
    HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup begin: vmxon_pa=0x%llX "
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
    const u64 hostCr3 = Vcpu->HostCr3;
    const u64 hostCr4 = __readcr4();
    const u64 guestCr3 = __readcr3();

    if (!IsCanonical(gdtBase) || !IsCanonical(idtBase) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, csSelector, false) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, ssSelector, false) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, dsSelector, true) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, esSelector, true) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, fsSelector, true) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, gsSelector, true) ||
        !IsGdtSelectorUsable(gdtBase, gdtLimit, trSelector, false) ||
        (ldtrSelector != 0 &&
         !IsGdtSelectorUsable(gdtBase, gdtLimit, ldtrSelector, false)) ||
        !IsValidCr3(hostCr3, hostCr4) || !IsValidCr3(guestCr3, hostCr4) ||
        tssBase == 0) {
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup rejected host/guest selector or CR3 "
                         "state: gdt=0x%llX/0x%X idt=0x%llX/0x%X cs=0x%04X "
                         "ss=0x%04X tr=0x%04X cr3=0x%llX host_cr3=0x%llX\n",
                         cpuId, gdtBase, gdtLimit, idtBase, idtLimit, csSelector,
                         ssSelector, trSelector, guestCr3, hostCr3);
        return false;
    }

    // The current guest-state builder does not decode an LDT descriptor base.
    // Refuse a non-empty LDTR instead of writing a guessed base and letting
    // VMLAUNCH fail with invalid guest state
    if (ldtrSelector != 0) {
        HV_VERBOSE_PRINT("[HV] VMCS setup rejected a non-empty LDTR 0x%04X\n",
                         ldtrSelector);
        return false;
    }

    // ==============================================================================
    // Host State Configuration
    // ==============================================================================
    VmWriteChecked(HOST_CR0, hostCr0);

    // set host CR3 to system directory table base
    VmWriteChecked(HOST_CR3, hostCr3);

    VmWriteChecked(HOST_CR4, hostCr4);

    // host selectors
    VmWriteChecked(HOST_CS_SELECTOR, csSelector & 0xFFF8);
    VmWriteChecked(HOST_SS_SELECTOR, ssSelector & 0xFFF8);
    VmWriteChecked(HOST_DS_SELECTOR, dsSelector & 0xFFF8);
    VmWriteChecked(HOST_ES_SELECTOR, esSelector & 0xFFF8);
    VmWriteChecked(HOST_FS_SELECTOR, fsSelector & 0xFFF8);
    VmWriteChecked(HOST_GS_SELECTOR, gsSelector & 0xFFF8);
    VmWriteChecked(HOST_TR_SELECTOR, trSelector & 0xFFF8);

    // host base addresses
    VmWriteChecked(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    VmWriteChecked(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
    VmWriteChecked(HOST_EFER, __readmsr(MSR_IA32_EFER));
    VmWriteChecked(HOST_TR_BASE, tssBase);
    VmWriteChecked(HOST_GDTR_BASE, gdtBase);
    VmWriteChecked(HOST_IDTR_BASE, idtBase);

    // host sysenter
    VmWriteChecked(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    VmWriteChecked(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmWriteChecked(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    // host RIP/RSP (exit handler)
    VmWriteChecked(HOST_RSP, Vcpu->HostStackTop);
    VmWriteChecked(HOST_RIP, reinterpret_cast<u64>(HvVmExitEntryPoint));

    // CET supervisor state is loaded by VM-exit/VM-entry controls rather than
    // by XSAVES.  Keep the host and initial guest copies identical; later
    // guest WRMSR operations update the guest VMCS fields in the exit handler.
    if (g_CetVmcsEnabled) {
        const u64 hostSCet = __readmsr(MSR_IA32_S_CET);
        const u64 hostSsp = __readmsr(MSR_IA32_PL0_SSP);
        const u64 hostInterruptSspTable =
            __readmsr(MSR_IA32_INTERRUPT_SSP_TABLE);
        if (!VmWriteChecked(HOST_S_CET, hostSCet) ||
            !VmWriteChecked(HOST_SSP, hostSsp) ||
            !VmWriteChecked(HOST_INTR_SSP_TABLE, hostInterruptSspTable)) {
            return 0;
        }
    }


    // ==============================================================================
    // Guest State Configuration
    // ==============================================================================

    // control registers
    VmWriteChecked(GUEST_CR0, AdjustCr0(__readcr0()));
    VmWriteChecked(GUEST_CR3, guestCr3);
    VmWriteChecked(GUEST_CR4, AdjustCr4(hostCr4));
    VmWriteChecked(GUEST_DR7, 0x400);

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
    VmWriteChecked(GUEST_CS_LIMIT, HvGetSegmentLimit(GetCs()));
    VmWriteChecked(GUEST_SS_LIMIT, HvGetSegmentLimit(GetSs()));
    VmWriteChecked(GUEST_DS_LIMIT, HvGetSegmentLimit(GetDs()));
    VmWriteChecked(GUEST_ES_LIMIT, HvGetSegmentLimit(GetEs()));
    VmWriteChecked(GUEST_FS_LIMIT, HvGetSegmentLimit(GetFs()));
    VmWriteChecked(GUEST_GS_LIMIT, HvGetSegmentLimit(GetGs()));
    VmWriteChecked(GUEST_LDTR_LIMIT, HvGetSegmentLimit(ldtrSelector));
    VmWriteChecked(GUEST_TR_LIMIT, HvGetSegmentLimit(trSelector));
    VmWriteChecked(GUEST_GDTR_LIMIT, GetGdtLimit());
    VmWriteChecked(GUEST_IDTR_LIMIT, GetIdtLimit());

    // guest access rights
    VmWriteChecked(GUEST_CS_AR_BYTES, HvGetSegmentAr(GetCs()));
    VmWriteChecked(GUEST_SS_AR_BYTES, HvGetSegmentAr(GetSs()));
    VmWriteChecked(GUEST_DS_AR_BYTES, HvGetSegmentAr(GetDs()));
    VmWriteChecked(GUEST_ES_AR_BYTES, HvGetSegmentAr(GetEs()));
    VmWriteChecked(GUEST_FS_AR_BYTES, HvGetSegmentAr(GetFs()));
    VmWriteChecked(GUEST_GS_AR_BYTES, HvGetSegmentAr(GetGs()));
    VmWriteChecked(GUEST_LDTR_AR_BYTES, HvGetSegmentAr(ldtrSelector));
    VmWriteChecked(GUEST_TR_AR_BYTES, HvGetSegmentAr(trSelector));

    // guest base addresses
    VmWriteChecked(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    VmWriteChecked(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
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
    VmWriteChecked(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    VmWriteChecked(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmWriteChecked(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    VmWriteChecked(GUEST_EFER, __readmsr(MSR_IA32_EFER));

    // PAT (Page Attribute Table)
    u64 pat = __readmsr(MSR_IA32_PAT);
    VmWriteChecked(GUEST_PAT, pat);
    VmWriteChecked(HOST_PAT, pat);

    if (g_CetVmcsEnabled) {
        const u64 guestSCet = __readmsr(MSR_IA32_S_CET);
        const u64 guestSsp = __readmsr(MSR_IA32_PL0_SSP);
        const u64 guestInterruptSspTable =
            __readmsr(MSR_IA32_INTERRUPT_SSP_TABLE);
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
    VmWriteChecked(GUEST_DEBUGCTL, 0);
    VmWriteChecked(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    VmWriteChecked(GUEST_SM_BASE, 0);

    // guest RIP/RSP
    if (!GuestIp || !GuestSp ||
        !IsCanonical(reinterpret_cast<u64>(GuestIp)) ||
        !IsCanonical(reinterpret_cast<u64>(GuestSp))) return false;
    VmWriteChecked(GUEST_RIP, reinterpret_cast<u64>(GuestIp));
    VmWriteChecked(GUEST_RSP, reinterpret_cast<u64>(GuestSp));
    // KeIpiGenericCall invokes this callback with IF cleared. The guest starts
    // on the callback continuation and then returns to ordinary kernel code;
    // it must be interruptible or the clock/IPI path will stop making progress
    u64 guestRflags = GetRflags();
    const u64 callbackRflags = guestRflags;
    guestRflags |= (1ULL << 9);                 // IF
    guestRflags |= (1ULL << 1);                 // architectural fixed bit
    guestRflags &= ~((1ULL << 17) |             // VM (invalid in long mode)
                      (1ULL << 19) |             // VIF
                      (1ULL << 20));             // VIP
    HV_VERBOSE_PRINT("[HV] CPU %u guest launch flags: source=0x%llX "
                     "guest=0x%llX source_if=%u guest_if=%u irql=%u "
                     "guest_sp=0x%llX guest_ip=0x%llX\n", cpuId,
                     callbackRflags, guestRflags,
                     (callbackRflags & (1ULL << 9)) != 0 ? 1U : 0U,
                     (guestRflags & (1ULL << 9)) != 0 ? 1U : 0U,
                     static_cast<ULONG>(KeGetCurrentIrql()),
                     reinterpret_cast<u64>(GuestSp),
                     reinterpret_cast<u64>(GuestIp));
    if (!VmWriteChecked(GUEST_RFLAGS, guestRflags)) return false;

    // ==============================================================================
    // VM Execution Controls
    // ==============================================================================

    const u32 pinCtlMsr = ControlMsr(Vcpu->VmxBasic,
                                     MSR_IA32_VMX_PINBASED_CTLS,
                                     MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    const u32 procCtlMsr = ControlMsr(Vcpu->VmxBasic,
                                      MSR_IA32_VMX_PROCBASED_CTLS,
                                      MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    const u32 exitCtlMsr = ControlMsr(Vcpu->VmxBasic,
                                      MSR_IA32_VMX_EXIT_CTLS,
                                      MSR_IA32_VMX_TRUE_EXIT_CTLS);
    const u32 entryCtlMsr = ControlMsr(Vcpu->VmxBasic,
                                       MSR_IA32_VMX_ENTRY_CTLS,
                                       MSR_IA32_VMX_TRUE_ENTRY_CTLS);

    u32 pinCtl = AdjustControls(0, pinCtlMsr);
    // Intel requires a few reserved pin bits to be one (normally 0x16).
    // Only reject controls that cause exits or require interrupt injection;
    // rejecting the mandatory mask would make VMX fail on mainstream CPUs.
    constexpr u32 pinExitControls = PIN_BASED_EXTERNAL_INTERRUPT_EXITING |
                                     PIN_BASED_NMI_EXITING |
                                     PIN_BASED_VIRTUAL_NMIS |
                                     PIN_BASED_PREEMPTION_TIMER |
                                     PIN_BASED_POSTED_INTERRUPTS;
    if ((pinCtl & pinExitControls) != 0 ||
        (pinCtl & ~ControlMandatoryOn(pinCtlMsr)) != 0) {
        return false;
    }
    VmWriteChecked(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS, pinCtl);
    VmWriteChecked(CONTROL_EXCEPTION_BITMAP, 0);
    VmWriteChecked(CONTROL_VM_ENTRY_INTR_INFO_FIELD, 0);
    VmWriteChecked(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
    VmWriteChecked(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, 0);

    // Keep the optional instruction controls in sync with CPUID so Windows
    // does not see RDTSCP/INVPCID/XSAVES in CPUID and then receive #UD in the
    // guest because VMX secondary controls were left disabled.
    u32 secondaryRequested = 0;
    int cpuidRegs[4] = {};
    __cpuid(cpuidRegs, 0);
    const int maxBasicLeaf = cpuidRegs[0];
    if (maxBasicLeaf >= 7) {
        __cpuidex(cpuidRegs, 7, 0);
        if (cpuidRegs[1] & (1 << 10)) secondaryRequested |= SECONDARY_ENABLE_INVPCID;
    }
    if (g_XsavesEnabled) secondaryRequested |= SECONDARY_ENABLE_XSAVES;
    // XSAVES is enabled only after InitializeVmxFeatureContract() verified the
    // compacted save size, IA32_XSS enumeration, and paired CET controls.
    // RDTSCP/INVPCID are ordinary guest instructions and are safe to expose
    // when the CPU advertises them.
    __cpuidex(cpuidRegs, 0x80000000, 0);
    const u32 maxExtendedLeaf = static_cast<u32>(cpuidRegs[0]);
    if (maxExtendedLeaf >= 0x80000001) {
        __cpuidex(cpuidRegs, 0x80000001, 0);
        if (cpuidRegs[3] & (1 << 27)) secondaryRequested |= SECONDARY_ENABLE_RDTSCP;
    }

    // MSR handling is part of the supported VM-exit contract. CPUID is
    // architecturally intercepted in VMX non-root mode and has no primary
    // control bit; VmExitHandler handles that exit directly.
    u32 requestedPrimary = CPU_BASED_USE_MSR_BITMAPS;
    if (secondaryRequested) requestedPrimary |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
    u32 procCtl = AdjustControls(requestedPrimary, procCtlMsr);
    if ((procCtl & CPU_BASED_USE_MSR_BITMAPS) == 0) return false;
    if (secondaryRequested &&
        (procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) == 0) return false;
    // Some Intel generations force CR3-load/store and other controls to one
    // in the capability MSR.  These controls are not requests from this
    // monitor; they must be treated as architectural mandatory bits, not as
    // unsupported optional exits.  In particular, CR3 access is handled by
    // HandleCrAccess so KPTI context switches remain valid.
    constexpr u32 supportedPrimary =
        CPU_BASED_USE_MSR_BITMAPS |
        CPU_BASED_ACTIVATE_TERTIARY_CONTROLS |
        CPU_BASED_ACTIVATE_SECONDARY_CONTROLS |
        CPU_BASED_CR3_LOAD_EXITING |
        CPU_BASED_CR3_STORE_EXITING;
    // AdjustControls also applies mandatory-one bits from the capability MSR.
    // Only the two controls handled by this monitor may be present; accepting
    // an unknown forced control can create an unhandled VM-exit loop.
    if (procCtl & ~(supportedPrimary | ControlMandatoryOn(procCtlMsr))) return false;
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
    if (procCtl & unsupportedPrimary) return false;
    if (!VmWriteChecked(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, procCtl)) return false;

    u32 secCtl = 0;
    if (procCtl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
        secCtl = AdjustControls(secondaryRequested, MSR_IA32_VMX_PROCBASED_CTLS2);
        if ((secCtl & secondaryRequested) != secondaryRequested) return false;
        // No EPT/VPID/APIC virtualization/nested controls are implemented.
        // Refuse any mandatory secondary bit outside the exact instruction
        // pass-through set selected from CPUID above.
        if (secCtl & ~secondaryRequested) return false;
    }
    if (!VmWriteChecked(CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, secCtl)) return false;

    // Recent Intel processors may require primary control bit 17, which
    // activates the 64-bit tertiary controls field. Intel capability MSRs
    // encode mandatory-one bits in the low half; those bits must be written
    // even when this monitor does not request optional tertiary features.
    if (procCtl & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS) {
        u64 tertiaryCtl = 0;
        __try {
            tertiaryCtl = AdjustControls64(0, MSR_IA32_VMX_PROCBASED_CTLS3);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        if (!VmWriteChecked(
                CONTROL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                tertiaryCtl)) {
            HV_VERBOSE_PRINT("[HV] CPU %u tertiary VMX controls write failed: "
                             "0x%llX\n", cpuId, tertiaryCtl);
            return false;
        }
        HV_VERBOSE_PRINT("[HV] CPU %u tertiary VMX controls: 0x%llX\n",
                         cpuId, tertiaryCtl);
    }

    if (!VmWriteChecked(CONTROL_MSR_BITMAP_ADDRESS, Vcpu->MsrBitmapPhys)) return false;
    if (g_XsavesEnabled &&
        !VmWriteChecked(CONTROL_XSS_EXITING_BITMAP, 0)) {
        return false;
    }

    // Bit 9: Host Address Space Size (Must be 1 for x64 Host)
    u32 requestedExit = VM_EXIT_HOST_ADDRESS_SPACE_SIZE |
                        VM_EXIT_LOAD_HOST_EFER |
                        VM_EXIT_LOAD_HOST_PAT;
    if (g_CetVmcsEnabled) requestedExit |= VM_EXIT_LOAD_CET_STATE;
    u32 exitCtl = AdjustControls(requestedExit, exitCtlMsr);
    if ((exitCtl & requestedExit) != requestedExit) return false;
    u32 supportedExit = requestedExit;
    if (exitCtl & ~(supportedExit | ControlMandatoryOn(exitCtlMsr))) return false;
    if (!VmWriteChecked(CONTROL_VM_EXIT_CONTROLS, exitCtl)) return false;

    // Bit 9: IA-32e Mode Guest (Must be 1 for x64 Guest)
    u32 requestedEntry = VM_ENTRY_IA32E_MODE_GUEST |
                         VM_ENTRY_LOAD_GUEST_EFER |
                         VM_ENTRY_LOAD_GUEST_PAT;
    if (g_CetVmcsEnabled) requestedEntry |= VM_ENTRY_LOAD_CET_STATE;
    u32 entryCtl = AdjustControls(requestedEntry, entryCtlMsr);
    if ((entryCtl & requestedEntry) != requestedEntry) return false;
    u32 supportedEntry = requestedEntry;
    if (entryCtl & ~(supportedEntry | ControlMandatoryOn(entryCtlMsr))) return false;
    if (!VmWriteChecked(CONTROL_VM_ENTRY_CONTROLS, entryCtl)) return false;

    // Set CR0/CR4 Guest/Host Masks
    const u64 guestCr0 = AdjustCr0(__readcr0());
    const u64 guestCr4 = AdjustCr4(__readcr4());

    VmWriteChecked(GUEST_CR0, guestCr0);
    VmWriteChecked(GUEST_CR4, guestCr4);

    VmWriteChecked(CONTROL_CR0_GUEST_HOST_MASK, 0ULL);
    VmWriteChecked(CONTROL_CR0_READ_SHADOW, guestCr0);

    VmWriteChecked(CONTROL_CR4_GUEST_HOST_MASK, CR4_VMXE);
    VmWriteChecked(CONTROL_CR4_READ_SHADOW, guestCr4 & ~CR4_VMXE);

    const bool success = mutableVcpu->VmcsWriteFailed == 0;
    HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup %s: guest_cr3=0x%llX "
                     "guest_rsp=0x%llX guest_rip=0x%llX guest_rflags=0x%llX "
                     "pin=0x%08X proc=0x%08X sec=0x%08X exit=0x%08X "
                     "entry=0x%08X cet=%u xsaves=%u\n", cpuId,
                     success ? "succeeded" : "FAILED", __readcr3(),
                     reinterpret_cast<u64>(GuestSp),
                     reinterpret_cast<u64>(GuestIp), guestRflags, pinCtl,
                     procCtl, secCtl, exitCtl, entryCtl,
                     g_CetVmcsEnabled ? 1U : 0U, g_XsavesEnabled ? 1U : 0U);
    if (success) {
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS host: cr0=0x%llX cr3=0x%llX "
                         "cr4=0x%llX rip=0x%llX rsp=0x%llX cs=0x%llX "
                         "ss=0x%llX tr=0x%llX\n", cpuId,
                         HvVmRead(HOST_CR0), HvVmRead(HOST_CR3),
                         HvVmRead(HOST_CR4), HvVmRead(HOST_RIP),
                         HvVmRead(HOST_RSP), HvVmRead(HOST_CS_SELECTOR),
                         HvVmRead(HOST_SS_SELECTOR),
                         HvVmRead(HOST_TR_SELECTOR));
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS guest: cr0=0x%llX cr3=0x%llX "
                         "cr4=0x%llX rip=0x%llX rsp=0x%llX rflags=0x%llX "
                         "cs=0x%llX ss=0x%llX cet=0x%llX ssp=0x%llX "
                         "ist=0x%llX\n", cpuId, HvVmRead(GUEST_CR0),
                         HvVmRead(GUEST_CR3), HvVmRead(GUEST_CR4),
                         HvVmRead(GUEST_RIP), HvVmRead(GUEST_RSP),
                         HvVmRead(GUEST_RFLAGS), HvVmRead(GUEST_CS_SELECTOR),
                         HvVmRead(GUEST_SS_SELECTOR),
                         g_CetVmcsEnabled ? HvVmRead(GUEST_S_CET) : 0ULL,
                         g_CetVmcsEnabled ? HvVmRead(GUEST_SSP) : 0ULL,
                         g_CetVmcsEnabled ? HvVmRead(GUEST_INTR_SSP_TABLE)
                                           : 0ULL);
    }
    return success;
}
// ==============================================================================
// Launch Logic
// ==============================================================================


// Called by the fixed-frame assembly IPI wrapper.  It performs every action
// that may need a compiler-generated stack frame, then returns before
// VMLAUNCH so the wrapper can own the successful guest continuation.
extern "C" ULONG PrepareHvCallback(ULONG_PTR Context, void* GuestSp, void* GuestIp) {
    UNREFERENCED_PARAMETER(Context);
    if (!g_VcpuData) return 0;
    if (!GuestSp || !GuestIp) return 0;

    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return 0;

    // Debug bring-up: return normally on all non-target processors. Do this
    // before publishing State so StartHypervisor can distinguish "skipped"
    // CPUs from real VMX failures.
    if (!ShouldLaunchOnThisProcessor(id)) {
        return 0;
    }

    VcpuContext* vcpu = &g_VcpuData[id];

    HV_VERBOSE_PRINT("[HV] CPU %u prepare begin: guest_sp=0x%llX guest_ip=0x%llX "
                     "state=%ld\n", id, reinterpret_cast<u64>(GuestSp),
                     reinterpret_cast<u64>(GuestIp), vcpu->State);

    if (InterlockedCompareExchange(&vcpu->State,
                                   VcpuStarting,
                                   VcpuUninitialized) != VcpuUninitialized) {
        return 0;
    }
    InterlockedExchange(&vcpu->LaunchStage, 1);

    volatile bool vmxActive = false;
    volatile bool cr4Prepared = false;
    __try {
        // Recheck the immutable feature contract on the processor that will
        // execute VMXON. This catches a heterogeneous package whose E-core
        // capability MSRs do not match the boot processor.
        int localCpuid[4] = {};
        __cpuid(localCpuid, 0);
        if (localCpuid[0] < 0xD) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        __cpuidex(localCpuid, 1, 0);
        if ((localCpuid[2] & (1 << 5)) == 0 ||
            (localCpuid[2] & (1 << 31)) != 0) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (!EnsureFeatureControlForVmx()) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        __cpuidex(localCpuid, 0xD, 0);
        const u64 localSupportedXcr0 = static_cast<u32>(localCpuid[0]) |
                                       (static_cast<u64>(static_cast<u32>(localCpuid[3])) << 32);
        const u64 localCr4 = __readcr4();
        const u64 localCr0 = __readcr0();
        if ((localCr0 & ((1ULL << 2) | (1ULL << 3))) != 0) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        const bool localCet = (localCr4 & CR4_CET) != 0;
        if (localCet != (g_CetVmcsEnabled != 0)) {
            HV_VERBOSE_PRINT("[HV] CPU %u local CR4.CET contract mismatch: "
                             "cr4=0x%llX global_cet_vmcs=%u\n", id, localCr4,
                             g_CetVmcsEnabled ? 1U : 0U);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        u64 localXcr0 = 0;
        __try {
            localXcr0 = _xgetbv(0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localXcr0 & ~localSupportedXcr0) != 0 ||
            (localXcr0 & 0x3ULL) != 0x3ULL ||
            static_cast<u32>(localCpuid[1]) > VMEXIT_XSAVE_MAX) {
            HV_VERBOSE_PRINT("[HV] CPU %u local XCR0/XSAVE contract mismatch: "
                             "xcr0=0x%llX supported=0x%llX frame=%lu\n",
                             id, localXcr0, localSupportedXcr0,
                             static_cast<ULONG>(localCpuid[1]));
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        __cpuidex(localCpuid, 0xD, 1);
        const u32 localXsaveFeatures = static_cast<u32>(localCpuid[0]);
        const u64 localXssMask = (static_cast<u32>(localCpuid[2]) |
                                  (static_cast<u64>(static_cast<u32>(localCpuid[3])) << 32)) &
                                 ~(1ULL << 63);
        u64 localXss = 0;
        const bool localXssRead = ReadMsrSafe(MSR_IA32_XSS, &localXss);
        if (g_XsavesEnabled && !localXssRead) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((localXssRead && (localXss & ~localXssMask) != 0) ||
            (localXssRead && (localXss & ~g_EnumeratedXssMask) != 0) ||
            (!g_XsavesEnabled && localXssRead && localXss != 0) ||
            (localXssRead && (localXss & IA32_XSS_CET_S) != 0)) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (localXssRead && (localXss & IA32_XSS_IPT) != 0) {
            u64 localPtControl = 0;
            if (!ReadMsrSafe(MSR_IA32_RTIT_CTL, &localPtControl) ||
                localPtControl != 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        if (g_XsavesEnabled) {
            u64 localEnumeratedXss = 0;
            u32 localXsaveStateSize = 0;
            const bool localXsaveLayoutValid =
                ComputeXsaveAreaSize(localXcr0, g_XsavesMask,
                                     &localEnumeratedXss,
                                     &localXsaveStateSize);
            if ((localXsaveFeatures & CPUID_D1_XSAVES) == 0 ||
                (g_XsavesMask & ~localXssMask) != 0 ||
                !localXsaveLayoutValid ||
                localEnumeratedXss != localXssMask ||
                localXsaveStateSize != g_XsaveStateSize ||
                localXsaveStateSize > VMEXIT_XSAVE_MAX ||
                !VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                                  SECONDARY_ENABLE_XSAVES)) {
                HV_VERBOSE_PRINT("[HV] CPU %u local XSAVES layout mismatch: "
                                 "features=0x%X xss=0x%llX fixed=0x%llX "
                                 "frame=%lu expected=%lu\n", id,
                                 localXsaveFeatures, localXssMask, g_XsavesMask,
                                 static_cast<ULONG>(localXsaveStateSize),
                                 static_cast<ULONG>(g_XsaveStateSize));
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        } else if (static_cast<u32>(localCpuid[1]) != g_XsaveStateSize) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if (g_CetVmcsEnabled) {
            u64 localVmxBasic = 0;
            if (!ReadMsrSafe(MSR_IA32_VMX_BASIC, &localVmxBasic)) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            if ((localVmxBasic & VMX_BASIC_NO_HW_ERROR_CODE) == 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            const u32 localExitMsr = ControlMsr(localVmxBasic,
                                                MSR_IA32_VMX_EXIT_CTLS,
                                                MSR_IA32_VMX_TRUE_EXIT_CTLS);
            const u32 localEntryMsr = ControlMsr(localVmxBasic,
                                                 MSR_IA32_VMX_ENTRY_CTLS,
                                                 MSR_IA32_VMX_TRUE_ENTRY_CTLS);
            if (!VmxControlAllows(localExitMsr, VM_EXIT_LOAD_CET_STATE) ||
                !VmxControlAllows(localEntryMsr, VM_ENTRY_LOAD_CET_STATE)) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
            u64 localSCet = 0;
            u64 localPl0 = 0;
            u64 localPl1 = 0;
            u64 localPl2 = 0;
            u64 localIst = 0;
            if (!ReadMsrSafe(MSR_IA32_S_CET, &localSCet) ||
                !ReadMsrSafe(MSR_IA32_PL0_SSP, &localPl0) ||
                !ReadMsrSafe(MSR_IA32_PL1_SSP, &localPl1) ||
                !ReadMsrSafe(MSR_IA32_PL2_SSP, &localPl2) ||
                !ReadMsrSafe(MSR_IA32_INTERRUPT_SSP_TABLE, &localIst) ||
                localSCet != 0 || localPl0 != 0 || localPl1 != 0 ||
                localPl2 != 0 || localIst != 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        HV_VERBOSE_PRINT("[HV] CPU %u local contract: CR4=0x%llX XSAVES=%u "
                         "XSS=0x%llX CET_VMCS=%u\n", id, localCr4,
                         g_XsavesEnabled ? 1U : 0U,
                         g_XsavesEnabled ? localXss : 0ULL,
                         g_CetVmcsEnabled ? 1U : 0U);
        vcpu->VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
        vcpu->RevisionId = static_cast<u32>(vcpu->VmxBasic) &
                           VMX_BASIC_REVISION_MASK;
        const u64 vcpuRegionSize = (vcpu->VmxBasic >> 32) & 0x1FFFULL;
        if (((vcpu->VmxBasic >> 50) & 0xFULL) != 6 ||
            vcpuRegionSize == 0 || vcpuRegionSize > PAGE_SIZE) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((vcpu->VmxBasic & VMX_BASIC_PHYSICAL_ADDRESS_32) &&
            (vcpu->VmxOnPhys > 0xFFFFFFFFULL ||
             vcpu->VmcsPhys > 0xFFFFFFFFULL ||
             vcpu->MsrBitmapPhys > 0xFFFFFFFFULL)) {
            HV_VERBOSE_PRINT("[HV] Processor %u requires 32-bit VMX physical addresses\n", id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        if ((vcpu->HostStackTop & 0x3FULL) != 0 ||
            ((vcpu->HostStackTop - VMEXIT_FRAME_SIZE) & 0x3FULL) != 0) {
            HV_VERBOSE_PRINT("[HV] Processor %u has an unaligned VM-exit XSAVE frame\n", id);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        *static_cast<u32*>(vcpu->VmxOnVirt) = vcpu->RevisionId;
        *static_cast<u32*>(vcpu->VmcsVirt) = vcpu->RevisionId;
        if (!ConfigureMsrBitmap(vcpu)) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        // IA32_KERNEL_GS_BASE is not part of VMCS host/guest state.  Reserve
        // one qword immediately below the VMX host stack top so the VM-exit
        // stub can restore the host value before it calls any C++ code.  The
        // guest starts with the same value; subsequent SWAPGS/WRMSR changes
        // are captured in GuestContext and restored before VMRESUME/IRET.
        const u64 hostKernelGs = __readmsr(MSR_IA32_KERNEL_GS_BASE);
        // The VM-exit stub allocates 0x1180 bytes below HOST_RSP and reserves
        // the final qword of that frame (offset 0x1178) for this shadow.
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                 (VMEXIT_FRAME_SIZE - VMEXIT_HOST_KGS_OFFSET)) = hostKernelGs;
        const u64 hostXcr0 = _xgetbv(0);
        u64 hostXss = 0;
        if (g_XsavesEnabled) {
            if (!ReadMsrSafe(MSR_IA32_XSS, &hostXss) ||
                (hostXss & ~g_EnumeratedXssMask) != 0) {
                InterlockedExchange(&vcpu->State, VcpuFailed);
                return 0;
            }
        }
        // The VM-exit frame reserves these slots immediately below the host
        // KERNEL_GS shadow.  They are read by arch.asm before any C++ code is
        // entered, so initialize them before VMXON/VMLAUNCH.
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                (VMEXIT_FRAME_SIZE - VMEXIT_HOST_XCR0_OFFSET)) = hostXcr0;
        *reinterpret_cast<u64*>(vcpu->HostStackTop -
                                (VMEXIT_FRAME_SIZE - VMEXIT_HOST_XSS_OFFSET)) = hostXss;
        vcpu->GuestGsBase = __readmsr(MSR_GS_BASE);
        vcpu->GuestKernelGsBase = hostKernelGs;
        // XCR0 is not saved/restored by VMX transitions.  The VM-exit stub
        // uses the live mask for XSAVE/XRSTOR, so retain the root value and
        // reject guest attempts to switch to a different mask (see the
        // XSETBV exit handler) rather than letting supervisor state bleed
        // into the host C++ continuation.
        vcpu->HostXcr0 = hostXcr0;
        vcpu->GuestXcr0 = hostXcr0;
        vcpu->HostXss = hostXss;
        vcpu->GuestXss = hostXss & g_SupportedXssMask;

        vcpu->OriginalCr0 = __readcr0();
        vcpu->OriginalCr4 = __readcr4();
        vcpu->HostCr3 = g_HostCr3;
        if ((vcpu->HostCr3 & ~static_cast<u64>(PAGE_SIZE - 1)) == 0) {
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        __writecr0(AdjustCr0(vcpu->OriginalCr0));
        __writecr4(AdjustCr4(vcpu->OriginalCr4 | CR4_VMXE));
        cr4Prepared = true;

        const u64 vmxonFlags = HvVmxOn(&vcpu->VmxOnPhys);
        if (!VmxOk(vmxonFlags)) {
            HV_VERBOSE_PRINT("[HV] CPU %u VMXON failed: flags=0x%llX cr0=0x%llX "
                             "cr4=0x%llX vmxon_pa=0x%llX\n", id, vmxonFlags,
                             __readcr0(), __readcr4(), vcpu->VmxOnPhys);
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }
        vmxActive = true;
        InterlockedExchange(&vcpu->LaunchStage, 2);
        InterlockedExchange(&vcpu->State, VcpuVmxOn);

        const u64 vmclearFlags = HvVmClear(&vcpu->VmcsPhys);
        const u64 vmptrldFlags = VmxOk(vmclearFlags)
                                     ? HvVmPtrLd(&vcpu->VmcsPhys)
                                     : vmclearFlags;
        if (!VmxOk(vmclearFlags) || !VmxOk(vmptrldFlags) ||
            !SetupVmcs(vcpu, GuestSp, GuestIp)) {
            HV_VERBOSE_PRINT("[HV] CPU %u VMCS setup failed: vmclear=0x%llX "
                             "vmptrld=0x%llX instruction_error=0x%llX\n", id,
                             vmclearFlags, vmptrldFlags,
                             VmxOk(vmptrldFlags) ? HvVmRead(VM_INSTRUCTION_ERROR) : 0ULL);
            HvVmxOff();
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        // VMX does not virtualize IA32_XSS. Enter the guest with the
        // restricted mask; the VM-exit stub switches back to HostXss before
        // calling C++ and restores this guest mask before VMRESUME.
        if (g_XsavesEnabled && !WriteMsrSafe(MSR_IA32_XSS, vcpu->GuestXss)) {
            HV_VERBOSE_PRINT("[HV] CPU %u failed to install guest IA32_XSS=0x%llX\n",
                             id, vcpu->GuestXss);
            HvVmxOff();
            (void)WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss);
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
            InterlockedExchange(&vcpu->State, VcpuFailed);
            return 0;
        }

        // The wrapper publishes Launched only after GuestStartThunk returns
        // from a successful VMLAUNCH. Until then this CPU is merely VMXON.
        InterlockedExchange(&vcpu->LaunchStage, 4);
        HV_VERBOSE_PRINT("[HV] CPU %u VMCS ready; entering VMLAUNCH: revision=0x%X "
                         "vmcs_pa=0x%llX host_rsp=0x%llX\n", id, vcpu->RevisionId,
                         vcpu->VmcsPhys, vcpu->HostStackTop);
        return 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        HV_VERBOSE_PRINT("[HV] CPU %u prepare raised an exception: vmx_active=%u "
                         "cr4_prepared=%u\n", id, vmxActive ? 1U : 0U,
                         cr4Prepared ? 1U : 0U);
        if (vmxActive) {
            HvVmxOff();
        }
        if (g_XsavesEnabled) {
            (void)WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss);
        }
        if (cr4Prepared) {
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
        }
        InterlockedExchange(&vcpu->State, VcpuFailed);
        return 0;
    }
}

extern "C" void AbortHvLaunch(u64 Rflags) {
    const u32 id = CurrentProcessorIndex();
    if (!g_VcpuData || id >= g_ProcessorCount) return;
    VcpuContext* vcpu = &g_VcpuData[id];

    // HvLaunchGuest returns this private token when its CR4.VMXE guard finds
    // that VMX operation is already inactive. In that case VMREAD/VMXOFF are
    // themselves invalid VMX instructions and must not be attempted.
    const bool vmxInstructionFailure = Rflags != VMX_LAUNCH_NOT_VMX_MAGIC;
    // ZF denotes VMfailValid, for which Intel guarantees VM_INSTRUCTION_ERROR
    // is readable.  CF denotes VMfailInvalid and has no valid error field.
    const u64 errorCode = vmxInstructionFailure && (Rflags & (1ULL << 6))
                              ? HvVmRead(VM_INSTRUCTION_ERROR)
                              : 0;
    vcpu->LastVmInstructionError = errorCode;
    InterlockedExchange(&vcpu->LaunchStage, 6);
    HV_VERBOSE_PRINT("[HV] VMLAUNCH failed on processor %u flags 0x%llX error 0x%llX vmx=%u\n",
                     id, Rflags, errorCode,
                     vmxInstructionFailure ? 1U : 0U);
    if (vmxInstructionFailure) {
        HvVmxOff();
    }
    if (g_XsavesEnabled) {
        (void)WriteMsrSafe(MSR_IA32_XSS, vcpu->HostXss);
    }
    __writecr0(vcpu->OriginalCr0);
    __writecr4(vcpu->OriginalCr4);
    InterlockedExchange(&vcpu->State, VcpuFailed);
}

// ==============================================================================
// Stop Logic
// ==============================================================================

// this ipi callback must return ULONG_PTR
ULONG_PTR StopHvCallback(ULONG_PTR Context) {
    UNREFERENCED_PARAMETER(Context);

    if (!g_VcpuData) return 0;
    const u32 id = CurrentProcessorIndex();
    if (id >= g_ProcessorCount) return 0;
    VcpuContext* vcpu = &g_VcpuData[id];
    const long state = vcpu->State;
    HV_VERBOSE_PRINT("[HV] CPU %u stop callback: state=%ld vmexits=%ld\n", id, state,
                     vcpu->VmExitCount);
    if (state == VcpuStopped || state == VcpuFailed || state == VcpuParked ||
        state == VcpuUninitialized) {
        return 0;
    }
    if (state == VcpuStarting) {
        // The owning launch callback is still on this processor. Do not mark
        // it stopped or free its VMX buffers until that callback publishes a
        // terminal state.
        return 0;
    }

    __try {
        if (state == VcpuLaunched) {
            // This VMCALL is handled in the guest.  The non-returning VMXOFF
            // path resumes at the instruction after VMCALL, so this callback
            // continues with a normal C++ epilogue.
            HvCall(HYPERVISOR_MAGIC, VMCALL_UNLOAD, 0, 0);
        } else if (state == VcpuVmxOn) {
            HvVmxOff();
        }

        // HvRestoreStateAndReturn has already restored the guest's current
        // CR0/CR3/CR4 (with VMXE cleared) before returning here.  Do not
        // overwrite a CR4 change Windows made while the monitor was active;
        // the original CR4 is only needed for the VMXON-but-not-launched
        // cleanup path below.
        if (state == VcpuVmxOn) {
            __writecr0(vcpu->OriginalCr0);
            __writecr4(vcpu->OriginalCr4);
        }
        InterlockedExchange(&vcpu->State, VcpuStopped);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Do not mark a live CPU as stopped after an exception: the VMX
        // structures may still be referenced by hardware.  StopHypervisor()
        // will refuse to free them and leave a recoverable leak instead.
        HV_VERBOSE_PRINT("[HV] CPU %u stop callback exception; retaining VMX state "
                         "state=%ld vmexits=%ld\n", id, vcpu->State,
                         vcpu->VmExitCount);
    }
    return 0;
}

// ==============================================================================
// Public API
// ==============================================================================

extern "C" NTSTATUS StartHypervisor() {
    if (InterlockedCompareExchange(&g_HvLifecycle, 1, 0) != 0) {
        return STATUS_DEVICE_BUSY;
    }
    auto rejectStart = [](NTSTATUS status) -> NTSTATUS {
        InterlockedExchange(&g_HvLifecycle, 0);
        return status;
    };
    // Keep this exported entry point safe even if a future caller bypasses
    // DriverEntry's initial gate.  The helper performs only read-only CPUID,
    // VMX capability, and IA32_FEATURE_CONTROL checks.
    if (!IsVmxSupported()) {
        DbgPrint("[HV] StartHypervisor rejected by the VMX capability gate\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    DbgPrint("[HV] StartHypervisor: contract CET_VMCS=%u XSAVES=%u\n",
             g_CetVmcsEnabled ? 1U : 0U, g_XsavesEnabled ? 1U : 0U);

    int regs[4] = {};
    __cpuidex(regs, 0x80000000, 0);
    const u32 maxExtendedLeaf = static_cast<u32>(regs[0]);
    if (maxExtendedLeaf >= 0x80000008) {
        __cpuidex(regs, 0x80000008, 0);
        const u8 reportedLinearBits = static_cast<u8>((regs[0] >> 8) & 0xFF);
        if (reportedLinearBits >= 48 && reportedLinearBits <= 57) {
            g_LinearAddressBits = ((__readcr4() & CR4_LA57) &&
                                   reportedLinearBits >= 57) ? 57 : 48;
        }
    }

    RtlZeroMemory(regs, sizeof(regs));
    if (g_XsavesEnabled) {
        // XSAVES uses the compacted XCR0|IA32_XSS layout.  CPUID.(D,1):EBX,
        // captured by the capability contract, is the bound that applies to
        // the VM-exit frame; leaf D.0:EBX only describes XCR0 state.
        u32 xsaveSize = g_XsaveStateSize;
        if (xsaveSize > VMEXIT_XSAVE_MAX ||
            xsaveSize > sizeof(GuestContext{}.FxArea)) {
            DbgPrint("[HV] XSAVES area too large: need %lu bytes, have %lu\n",
                     static_cast<ULONG>(xsaveSize),
                     static_cast<ULONG>(sizeof(GuestContext{}.FxArea)));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    } else {
        __cpuidex(regs, 0xD, 0);
        u32 xsaveSize = static_cast<u32>(regs[1]);
        if (xsaveSize > VMEXIT_XSAVE_MAX ||
            xsaveSize > sizeof(GuestContext{}.FxArea)) {
            DbgPrint("[HV] XSAVE area too large: need %lu bytes, have %lu\n",
                     static_cast<ULONG>(xsaveSize),
                     static_cast<ULONG>(sizeof(GuestContext{}.FxArea)));
            return rejectStart(STATUS_NOT_SUPPORTED);
        }
    }

    __try {
        g_VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HV] StartHypervisor rejected: IA32_VMX_BASIC read faulted\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    // Allocate all VMX regions below 4 GiB.  VMX_BASIC is per logical
    // processor on heterogeneous packages; using only the boot CPU's bit can
    // produce valid regions for one core and VMXON failure on another.
    // Four-kilobyte regions are cheap enough that the conservative address
    // limit is preferable to a cross-CPU allocation race.
    g_VmxRequires32BitPhysicalAddress = true;
    const u64 vmxRegionSize = (g_VmxBasic >> 32) & 0x1FFFULL;
    if (((g_VmxBasic >> 50) & 0xFULL) != 6 ||
        vmxRegionSize == 0 || vmxRegionSize > PAGE_SIZE) {
        DbgPrint("[HV] StartHypervisor rejected: VMX_BASIC=0x%llX regionSize=0x%llX\n",
                 g_VmxBasic, vmxRegionSize);
        return rejectStart(STATUS_NOT_SUPPORTED);
    }

    // Capture a kernel/system CR3 while attached to the system process.  Do
    // not use the CR3 observed inside the per-CPU IPI callback: that callback
    // can interrupt a thread in an arbitrary user address space, and VMX
    // would then load a CR3 that cannot map the host VM-exit stack.
    KAPC_STATE apcState{};
    KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(PsInitialSystemProcess),
                         &apcState);
    g_HostCr3 = __readcr3();
    KeUnstackDetachProcess(&apcState);
    if ((g_HostCr3 & ~static_cast<u64>(PAGE_SIZE - 1)) == 0) {
        DbgPrint("[HV] StartHypervisor rejected: system CR3 is invalid (0x%llX)\n",
                 g_HostCr3);
        return rejectStart(STATUS_NOT_SUPPORTED);
    }

    g_ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (g_ProcessorCount == 0) {
        DbgPrint("[HV] StartHypervisor rejected: no active processors\n");
        return rejectStart(STATUS_NOT_SUPPORTED);
    }
    DbgPrint("[HV] StartHypervisor: processors=%u host_cr3=0x%llX "
             "vmx_basic=0x%llX xsave_frame=%lu\n", g_ProcessorCount,
             g_HostCr3, g_VmxBasic, static_cast<ULONG>(g_XsaveStateSize));

    g_VcpuData = static_cast<VcpuContext*>(
        ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(VcpuContext) * g_ProcessorCount, TAG_HV00)
    );

    if (!g_VcpuData) return rejectStart(STATUS_INSUFFICIENT_RESOURCES);
    RtlZeroMemory(g_VcpuData, sizeof(VcpuContext) * g_ProcessorCount);

    for (u32 i = 0; i < g_ProcessorCount; i++) {
        g_VcpuData[i].VmxOnVirt     = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].VmxOnPhys);
        g_VcpuData[i].VmcsVirt      = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].VmcsPhys);
        g_VcpuData[i].MsrBitmapVirt = AllocContiguous(PAGE_SIZE, &g_VcpuData[i].MsrBitmapPhys);
        if (g_VcpuData[i].MsrBitmapVirt) RtlZeroMemory(g_VcpuData[i].MsrBitmapVirt, PAGE_SIZE);

        g_VcpuData[i].HostStack = ExAllocatePoolWithTag(NonPagedPoolNx, 0x8000, TAG_HVST);
        if (g_VcpuData[i].HostStack) {
            RtlZeroMemory(g_VcpuData[i].HostStack, 0x8000);
            g_VcpuData[i].HostStackTop  = reinterpret_cast<u64>(g_VcpuData[i].HostStack) + 0x8000;
            g_VcpuData[i].HostStackTop &= ~0x3FULL;
        }

        if (!g_VcpuData[i].VmxOnVirt || !g_VcpuData[i].VmcsVirt ||
            !g_VcpuData[i].MsrBitmapVirt || !g_VcpuData[i].HostStack) {
                DbgPrint("[HV] CPU %u allocation failed: vmxon=%u vmcs=%u "
                         "msr_bitmap=%u host_stack=%u\n", i,
                         g_VcpuData[i].VmxOnVirt ? 1U : 0U,
                         g_VcpuData[i].VmcsVirt ? 1U : 0U,
                         g_VcpuData[i].MsrBitmapVirt ? 1U : 0U,
                         g_VcpuData[i].HostStack ? 1U : 0U);
                InterlockedExchange(&g_HvLifecycle, 3);
                StopHypervisor();
                InterlockedExchange(&g_HvLifecycle, 0);
                return STATUS_INSUFFICIENT_RESOURCES;
        }
        DbgPrint("[HV] CPU %u allocations: vmxon_pa=0x%llX vmcs_pa=0x%llX "
                 "msr_bitmap_pa=0x%llX host_stack=0x%llX\n", i,
                 g_VcpuData[i].VmxOnPhys, g_VcpuData[i].VmcsPhys,
                 g_VcpuData[i].MsrBitmapPhys,
                 reinterpret_cast<u64>(g_VcpuData[i].HostStack));
    }

    KeIpiGenericCall(EnableHvCallback, 0);

    const u32 expected = ExpectedLaunchProcessorCount();
    u32 ok = 0;

    for (u32 i = 0; i < g_ProcessorCount; i++) {
        DbgPrint("[HV] CPU %u launch result: state=%ld stage=%ld vmexits=%ld "
                "reason=%ld action=%ld resumes=%ld rip=0x%llX instrerr=0x%llX\n",
                i,
                g_VcpuData[i].State,
                g_VcpuData[i].LaunchStage,
                g_VcpuData[i].VmExitCount,
                g_VcpuData[i].LastExitReason,
                g_VcpuData[i].LastExitAction,
                g_VcpuData[i].VmResumeAttempts,
                g_VcpuData[i].LastGuestRip,
                g_VcpuData[i].LastVmInstructionError);

        if (g_VcpuData[i].State == VcpuLaunched) {
            ok++;
        }
    }

    DbgPrint("[HV] Launched on %u/%u expected processors, active=%u\n",
            ok, expected, g_ProcessorCount);

    if (ok != expected) {
        DbgPrint("[HV] StartHypervisor rejected: only %u/%u expected processors entered VMX\n",
                ok, expected);

        InterlockedExchange(&g_HvLifecycle, 3);
        StopHypervisor();
        InterlockedExchange(&g_HvLifecycle, 0);
        return STATUS_NOT_SUPPORTED;
    }

    InterlockedExchange(&g_HvLifecycle, 2);
    return STATUS_SUCCESS;
}

static bool HasParkedVcpu() {
    if (!g_VcpuData) return false;
    for (u32 i = 0; i < g_ProcessorCount; ++i) {
        if (g_VcpuData[i].State == VcpuParked) return true;
    }
    return false;
}

// A parked processor has no architecturally valid guest continuation and may
// still execute the VM-exit image. Pin the driver object once, retain all VMX
// allocations, and return to the caller instead of blocking an unload thread.
static void PinImageForParkedCpu() {
    if (!g_HvDriverObject ||
        InterlockedCompareExchange(&g_HvImagePinned, 1, 0) != 0) {
        return;
    }
    ObReferenceObject(g_HvDriverObject);
    HV_VERBOSE_PRINT("[HV] parked CPU quarantined; driver image pinned\n");
}

extern "C" void StopHypervisor() {
    if (!g_VcpuData) {
        InterlockedCompareExchange(&g_HvLifecycle, 0, 3);
        return;
    }
    const long lifecycle = g_HvLifecycle;
    if (lifecycle == 1) {
        // A concurrent stop must not race a callback that is still preparing
        // VMX state. The owner of the start operation performs its own rollback.
        return;
    }
    if (lifecycle == 2) {
        InterlockedCompareExchange(&g_HvLifecycle, 3, 2);
    } else if (lifecycle == 0) {
        InterlockedCompareExchange(&g_HvLifecycle, 3, 0);
    }
    {
        // A parked processor has IF=0 and remains on the private VMX stack;
        // KeIpiGenericCall cannot wait for a callback from it. Detect this
        // state before broadcasting the normal unload VMCALL.
        if (HasParkedVcpu()) {
            PinImageForParkedCpu();
            InterlockedExchange(&g_HvLifecycle, 4);
            return;
        }
        // broadcast unload signal
        KeIpiGenericCall(StopHvCallback, 0);

        if (HasParkedVcpu()) {
            PinImageForParkedCpu();
            InterlockedExchange(&g_HvLifecycle, 4);
            return;
        }

        for (u32 i = 0; i < g_ProcessorCount; i++) {
            const long state = g_VcpuData[i].State;
            if (state == VcpuLaunched || state == VcpuVmxOn ||
                state == VcpuStarting ||
                state == VcpuParked) {
                // Do not free VMXON/VMCS/host-stack memory while a CPU may
                // still execute from it.  Leaking here is safer than a
                // deterministic use-after-free triple fault.
                HV_VERBOSE_PRINT("[HV] Refusing to free live VMX state on CPU %u "
                                 "(state %ld)\n", i, state);
                return;
            }
        }

        // free memory
        for (u32 i = 0; i < g_ProcessorCount; i++) {
            if (g_VcpuData[i].VmxOnVirt) MmFreeContiguousMemory(g_VcpuData[i].VmxOnVirt);
            if (g_VcpuData[i].VmcsVirt)  MmFreeContiguousMemory(g_VcpuData[i].VmcsVirt);
            if (g_VcpuData[i].MsrBitmapVirt) MmFreeContiguousMemory(g_VcpuData[i].MsrBitmapVirt);
            if (g_VcpuData[i].HostStack) ExFreePoolWithTag(g_VcpuData[i].HostStack, TAG_HVST);
        }
        ExFreePoolWithTag(g_VcpuData, TAG_HV00);
        g_VcpuData = nullptr;
        InterlockedExchange(&g_HvLifecycle, 0);
    }
}
