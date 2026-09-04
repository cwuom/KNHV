//
// Created by cwuom on 17 Feb 2026.
//

#include <intrin.h>
#include <ntddk.h>

#include "header/common.h"
#include "header/vmm.h"
#include "header/vmx.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject = nullptr;

#define HV_PASSIVE_PRINT(...) \
    do { \
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__); \
        } \
    } while (0)

static constexpr const char* kDriverContractTag =
    "V54-ALLCPU-STAGED-CANARY-COORDINATOR-LAST-INTEL-WAITPKG-IRETQ-5WORD-UNLOAD-HYPERDBG";
static constexpr ULONG kHvFatalBugCheck = 0x48564D58UL;
static constexpr ULONG_PTR kHvFatalUnloadIncomplete = 0x554E4C44ULL;
static constexpr ULONG_PTR kHvFatalUnloadCallbackState = 0x43425354ULL;

static bool RejectVmx(const char* reason) {
    HV_PASSIVE_PRINT("[HV] VMX gate rejected: %s\n", reason);
    return false;
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

static bool ReadCETState(u64* userCet,
                         u64* supervisorCet,
                         u64* xss,
                         u64* pl0Ssp,
                         u64* pl1Ssp,
                         u64* pl2Ssp,
                         u64* pl3Ssp,
                         u64* interruptSspTable,
                         bool readShadowStackMsrs) {
    if (!userCet || !supervisorCet || !xss || !pl0Ssp || !pl1Ssp ||
        !pl2Ssp || !pl3Ssp || !interruptSspTable) {
        return false;
    }

    __try {
        *userCet = __readmsr(MSR_IA32_U_CET);
        *supervisorCet = __readmsr(MSR_IA32_S_CET);
        *xss = __readmsr(MSR_IA32_XSS);
        if (readShadowStackMsrs) {
            *pl0Ssp = __readmsr(MSR_IA32_PL0_SSP);
            *pl1Ssp = __readmsr(MSR_IA32_PL1_SSP);
            *pl2Ssp = __readmsr(MSR_IA32_PL2_SSP);
            *pl3Ssp = __readmsr(MSR_IA32_PL3_SSP);
            *interruptSspTable = __readmsr(MSR_IA32_INTERRUPT_SSP_TABLE);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}


// Hardware/firmware gate.  VMX is a package-wide resource and cannot safely
// be claimed when another type-1 hypervisor already owns it.  Failing closed
// here is preferable to entering VMX with an unknown host state (which is how
// a malformed VM-entry turns into a triple fault).
bool IsVmxSupported() {
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 0);
    const int maxBasicLeaf = cpuInfo[0];
    HV_PASSIVE_PRINT("[HV] CPUID.0: max_basic=0x%X vendor=%08X-%08X-%08X\n",
             maxBasicLeaf, static_cast<ULONG>(cpuInfo[1]),
             static_cast<ULONG>(cpuInfo[3]), static_cast<ULONG>(cpuInfo[2]));
    if (maxBasicLeaf < 1) return RejectVmx("CPUID basic leaf 1 is unavailable");

    // VMX is an Intel architectural contract.  Do this check before any
    // capability MSR access so a spoofed or non-Intel CPUID cannot reach
    // VMX_BASIC and turn an unsupported instruction into a fatal fault.
    const bool genuineIntel =
        static_cast<u32>(cpuInfo[1]) == 0x756E6547U &&
        static_cast<u32>(cpuInfo[3]) == 0x49656E69U &&
        static_cast<u32>(cpuInfo[2]) == 0x6C65746EU;
    if (!genuineIntel) return RejectVmx("CPUID vendor is not GenuineIntel");

    __cpuidex(cpuInfo, 1, 0);
    const bool fxsrEnumerated = (static_cast<u32>(cpuInfo[3]) &
                                CPUID_1_EDX_FXSR) != 0;
    const bool xsaveEnumerated = (static_cast<u32>(cpuInfo[2]) &
                                  CPUID_1_ECX_XSAVE) != 0;
    const bool osxsaveEnabled = (static_cast<u32>(cpuInfo[2]) &
                                 CPUID_1_ECX_OSXSAVE) != 0;
    const u64 currentCr4 = __readcr4();
    const bool cr4OsxsaveEnabled = (currentCr4 & CR4_OSXSAVE) != 0;
    HV_PASSIVE_PRINT("[HV] CPUID.1:ECX=0x%08X\n", static_cast<ULONG>(cpuInfo[2]));
    HV_PASSIVE_PRINT("[HV] CPUID.1: VMX=%u XSAVE=%u OSXSAVE=%u hypervisor=%u CET_CR4=%u\n",
             (cpuInfo[2] & (1 << 5)) != 0 ? 1U : 0U,
             xsaveEnumerated ? 1U : 0U,
             osxsaveEnabled ? 1U : 0U,
             (cpuInfo[2] & (1 << 31)) != 0 ? 1U : 0U,
             (currentCr4 & CR4_CET) != 0 ? 1U : 0U);
    if (!(cpuInfo[2] & (1 << 5))) return RejectVmx("CPUID.1:ECX.VMX is clear");
    if (cpuInfo[2] & (1 << 31)) return RejectVmx("another hypervisor is active; nested VMX is disabled");
    // The VM-exit entry uses XSAVE when the OS has enabled it. Older Intel
    // processors, or kernels with OSXSAVE disabled, use the FXSAVE backend.
    // Both paths still require the legacy SSE save contract.
    // CR4.CET is a prerequisite for CET, but it is not by itself proof that
    // shadow-stack or IBT enforcement is enabled. Those controls live in
    // IA32_{U,S}_CET, while IA32_XSS advertises supervisor XSTATE components
    // that ordinary XSAVE/XRSTOR does not preserve. Read the complete state
    // before deciding which capability is outside this monitor's contract.
    HV_PASSIVE_PRINT("[HV] CR4=0x%llX\n", currentCr4);
    if ((currentCr4 & CR4_FRED) != 0) {
        return RejectVmx("FRED event delivery is active and unsupported");
    }
    const u64 currentCr0 = __readcr0();
    HV_PASSIVE_PRINT("[HV] CR0=0x%llX\n", currentCr0);
    // XSAVE(S)/XRSTOR(S) raise #NM while CR0.TS is set and #UD while EM is
    // set. The VM-exit entry stub cannot safely take either fault, so reject a
    // nonstandard lazy-FPU configuration before VMXON instead of risking a
    // fault on the private VMX stack.
    if ((currentCr0 & ((1ULL << 2) | (1ULL << 3))) != 0) {
        return RejectVmx("CR0.EM or CR0.TS blocks floating-point save");
    }

    u64 userCet = 0;
    u64 supervisorCet = 0;
    u64 xss = 0;
    u64 pl0Ssp = 0;
    u64 pl1Ssp = 0;
    u64 pl2Ssp = 0;
    u64 pl3Ssp = 0;
    u64 interruptSspTable = 0;
    __try {
        if (xsaveEnumerated && osxsaveEnabled && cr4OsxsaveEnabled) {
            const u64 xcr0 = _xgetbv(0);
            HV_PASSIVE_PRINT("[HV] XCR0=0x%llX\n", xcr0);
            if ((xcr0 & 0x3ULL) != 0x3ULL) {
                return RejectVmx("XCR0 lacks x87/SSE state");
            }
            __cpuidex(cpuInfo, 0xD, 0);
            const u64 supportedXcr0 = static_cast<u32>(cpuInfo[0]) |
                                      (static_cast<u64>(static_cast<u32>(cpuInfo[3])) << 32);
            if ((xcr0 & ~supportedXcr0) != 0) {
                return RejectVmx("XCR0 contains an unenumerated state component");
            }
        } else if (!fxsrEnumerated ||
                   (currentCr4 & CR4_OSFXSR) == 0 ||
                   (currentCr4 & CR4_OSXSAVE) != 0 ||
                   (currentCr4 & CR4_PKE) != 0) {
            return RejectVmx("legacy FXSAVE state is unavailable");
        } else {
            HV_PASSIVE_PRINT("[HV] XSTATE: using legacy FXSAVE backend\n");
        }
        // CPUID.0D.0 enumerates every XCR0 component the processor can
        // support, not only the components enabled by the running OS. The
        // VM-exit frame is sized from the live XCR0 below, so unsupported
        // future components must not reject a normal XCR0 such as 0x7.
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return RejectVmx("reading XCR0 faulted");
    }

    // CET MSRs are not present on every VMX-capable Intel processor.  Probe
    // the architectural feature first so ordinary XSAVE machines do not get
    // rejected merely because a newer MSR is absent.
    bool cetEnumerated = false;
    bool cetShadowStackEnumerated = false;
    if (maxBasicLeaf >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        cetShadowStackEnumerated =
            (static_cast<u32>(cpuInfo[2]) & CPUID_7_ECX_CET_SHSTK) != 0;
        cetEnumerated = cetShadowStackEnumerated ||
                        (static_cast<u32>(cpuInfo[3]) & CPUID_7_EDX_CET_IBT) != 0;
        const bool ptEnumerated =
            (static_cast<u32>(cpuInfo[1]) & CPUID_7_EBX_INTEL_PT) != 0;
        const bool cetIbtEnumerated =
            (static_cast<u32>(cpuInfo[3]) & CPUID_7_EDX_CET_IBT) != 0;
        const u32 cpuid7MaxSubleaf = static_cast<u32>(cpuInfo[0]);
        bool fredEnumerated = false;
        HV_PASSIVE_PRINT("[HV] CPUID.7.0: EBX=0x%08X ECX=0x%08X EDX=0x%08X "
                 "CET_SS=%u CET_IBT=%u PT=%u\n",
                 static_cast<ULONG>(cpuInfo[1]), static_cast<ULONG>(cpuInfo[2]),
                 static_cast<ULONG>(cpuInfo[3]), cetShadowStackEnumerated ? 1U : 0U,
                 cetIbtEnumerated ? 1U : 0U, ptEnumerated ? 1U : 0U);
        if (cpuid7MaxSubleaf >= 1) {
            __cpuidex(cpuInfo, 7, 1);
            fredEnumerated =
                (static_cast<u32>(cpuInfo[0]) & CPUID_7_1_EAX_FRED) != 0;
            HV_PASSIVE_PRINT("[HV] CPUID.7.1: EAX=0x%08X FRED=%u\n",
                     static_cast<ULONG>(cpuInfo[0]),
                     fredEnumerated ? 1U : 0U);
        }
        if (ptEnumerated) {
            u64 vmxMisc = 0;
            u64 ptControl = 0;
            if (!ReadMsrSafe(MSR_IA32_VMX_MISC, &vmxMisc) ||
                !ReadMsrSafe(MSR_IA32_RTIT_CTL, &ptControl)) {
                return RejectVmx("reading Intel PT capability state faulted");
            }
            HV_PASSIVE_PRINT("[HV] Intel PT policy: VMX_MISC=0x%llX post_vmxon=%u "
                     "RTIT_CTL=0x%llX guest=hidden\n",
                     vmxMisc, (vmxMisc & VMX_MISC_INTEL_PT) != 0 ? 1U : 0U,
                     ptControl);
            if ((ptControl & IA32_RTIT_CTL_TRACEEN) != 0) {
                return RejectVmx("Intel PT tracing is active and not virtualized");
            }
        }
        if (maxBasicLeaf >= 0x14) {
            __cpuidex(cpuInfo, 0x14, 0);
            HV_PASSIVE_PRINT("[HV] CPUID.14.0: EAX=0x%08X EBX=0x%08X ECX=0x%08X "
                     "EDX=0x%08X guest=hidden\n",
                     static_cast<ULONG>(cpuInfo[0]),
                     static_cast<ULONG>(cpuInfo[1]),
                     static_cast<ULONG>(cpuInfo[2]),
                     static_cast<ULONG>(cpuInfo[3]));
            if (static_cast<u32>(cpuInfo[0]) >= 1) {
                __cpuidex(cpuInfo, 0x14, 1);
                HV_PASSIVE_PRINT("[HV] CPUID.14.1: EAX=0x%08X EBX=0x%08X ECX=0x%08X "
                         "EDX=0x%08X\n",
                         static_cast<ULONG>(cpuInfo[0]),
                         static_cast<ULONG>(cpuInfo[1]),
                         static_cast<ULONG>(cpuInfo[2]),
                         static_cast<ULONG>(cpuInfo[3]));
            }
        }
        // CPUID advertises FRED capability, while CR4.FRED tells whether the
        // current host actually uses FRED event delivery.  An enumerated but
        // inactive feature does not alter the VMX host-state contract.
        if (fredEnumerated && (currentCr4 & CR4_FRED) != 0) {
            return RejectVmx("FRED event delivery is active and unsupported");
        }
    }
    bool xsavesEnumerated = false;
    bool xrstorsEnumerated = false;
    bool xfdEnumerated = false;
    if (maxBasicLeaf >= 0xD && xsaveEnumerated) {
        __cpuidex(cpuInfo, 0xD, 1);
        // Intel defines EAX[3] as the paired XSAVES/XRSTORS capability.
        // EAX[4] is extended feature disable (XFD), not XRSTORS.
        xsavesEnumerated = (cpuInfo[0] & CPUID_D1_XSAVES) != 0;
        xrstorsEnumerated = xsavesEnumerated;
        xfdEnumerated = (cpuInfo[0] & CPUID_D1_XFD) != 0;
        HV_PASSIVE_PRINT("[HV] CPUID.0D.1: EAX=0x%08X EBX=%u ECX=0x%08X EDX=0x%08X "
                 "XSAVES=%u XRSTORS=%u XFD=%u\n",
                 static_cast<ULONG>(cpuInfo[0]), static_cast<ULONG>(cpuInfo[1]),
                 static_cast<ULONG>(cpuInfo[2]), static_cast<ULONG>(cpuInfo[3]),
                 xsavesEnumerated ? 1U : 0U, xrstorsEnumerated ? 1U : 0U,
                 xfdEnumerated ? 1U : 0U);
    }
    if (xfdEnumerated) {
        u64 xfd = 0;
        u64 xfdError = 0;
        if (!ReadMsrSafe(MSR_IA32_XFD, &xfd) ||
            !ReadMsrSafe(MSR_IA32_XFD_ERR, &xfdError)) {
            return RejectVmx("reading XFD state faulted");
        }
        HV_PASSIVE_PRINT("[HV] XFD policy: IA32_XFD=0x%llX IA32_XFD_ERR=0x%llX "
                 "guest=hidden\n", xfd, xfdError);
        if (xfd != 0 || xfdError != 0) {
            return RejectVmx("active XFD state is not virtualized");
        }
    }
    if (cetEnumerated || (currentCr4 & CR4_CET) != 0) {
        if (!ReadCETState(&userCet, &supervisorCet, &xss,
                          &pl0Ssp, &pl1Ssp, &pl2Ssp, &pl3Ssp,
                          &interruptSspTable, cetShadowStackEnumerated)) {
            return RejectVmx("reading CET/XSS MSRs faulted");
        }
    } else if (xsavesEnumerated) {
        __try {
            xss = __readmsr(MSR_IA32_XSS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return RejectVmx("reading IA32_XSS faulted");
        }
    }
    HV_PASSIVE_PRINT("[HV] CET: IA32_U_CET=0x%llX IA32_S_CET=0x%llX "
             "IA32_XSS=0x%llX\n",
             userCet, supervisorCet, xss);
    HV_PASSIVE_PRINT("[HV] CET SSP: PL0=0x%llX PL1=0x%llX PL2=0x%llX "
             "PL3=0x%llX IST=0x%llX\n",
             pl0Ssp, pl1Ssp, pl2Ssp, pl3Ssp, interruptSspTable);

    if (!InitializeVmxFeatureContract()) {
        return RejectVmx("XSAVE/CET state cannot be preserved on this processor");
    }

    // Windows 11 25H2 commonly leaves CR4.CET set while CET state is inactive.
    // The host frame can preserve a selected CET_U component, but this build
    // does not expose or virtualize active user or supervisor CET state.
    if ((userCet & IA32_CET_ENABLE_MASK) != 0 || pl3Ssp != 0) {
        return RejectVmx("active user CET state is outside the safe VMX contract");
    }
    if ((supervisorCet & IA32_CET_ENABLE_MASK) != 0 ||
        pl0Ssp != 0 || pl1Ssp != 0 ||
        pl2Ssp != 0 || interruptSspTable != 0) {
        return RejectVmx("active supervisor CET state is outside the safe VMX contract");
    }
    if ((userCet & IA32_CET_ENABLE_MASK) != 0 &&
        (xss & IA32_XSS_CET_U) == 0) {
        return RejectVmx("CET_U is enabled without an XSAVES CET_U component");
    }
    if (xss != 0 && !IsXsavesEnabled()) {
        return RejectVmx("IA32_XSS is non-zero but XSAVES is unavailable");
    }
    HV_PASSIVE_PRINT("[HV] CET contract selected: VMCS=%u XSAVES=%u\n",
             IsCETVmcsEnabled() ? 1U : 0U,
             IsXsavesEnabled() ? 1U : 0U);
    __try {
        u64 featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);
        // Do not write IA32_FEATURE_CONTROL here.  Setting the lock bit is
        // irreversible until reset and can conflict with firmware, BitLocker,
        // or another type-1 monitor.  A driver that cannot prove VMXON is
        // already permitted must fail closed before allocating VMX state.
        HV_PASSIVE_PRINT("[HV] IA32_FEATURE_CONTROL=0x%llX\n", featureControl);
        if ((featureControl & (IA32_FEATURE_CONTROL_LOCK |
                               IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX)) !=
            (IA32_FEATURE_CONTROL_LOCK |
             IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX)) {
            return RejectVmx("IA32_FEATURE_CONTROL does not already permit VMXON");
        }

        const u64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
        HV_PASSIVE_PRINT("[HV] IA32_VMX_BASIC=0x%llX\n", vmxBasic);
        // VMX regions must be WB and fit in the 4-KiB region allocated below.
        if (((vmxBasic >> 50) & 0xFULL) != 6) {
            return RejectVmx("VMX region memory type is not write-back");
        }
        const u64 regionSize = (vmxBasic >> 32) & 0x1FFFULL;
        if (regionSize == 0 || regionSize > PAGE_SIZE) {
            return RejectVmx("VMX region size is outside the supported range");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return RejectVmx("reading VMX capability MSRs faulted");
    }

    // InitializeVmxFeatureContract calculated the compacted size from every
    // component in the immutable XSAVES mask. Leaf D.1:EBX alone only describes
    // the currently enabled XSS selection and can under-report this frame.
    const u32 xsaveSize = GetXsaveStateSize();
    // HvVmExitEntryPoint reserves the first 0x1000 bytes of its frame for the
    // ordinary XSAVE area; the GPR/GuestContext fields begin at that exact
    // offset. A larger area would overwrite the saved registers and corrupt
    // the VM-exit continuation.
    if (xsaveSize > VMEXIT_XSAVE_MAX ||
        xsaveSize > sizeof(GuestContext{}.FxArea)) {
        return RejectVmx("XSAVE area exceeds the VM-exit frame");
    }
    HV_PASSIVE_PRINT("[HV] VMX gate accepted: xsave_frame=%u cet_vmcs=%u xsaves=%u\n",
             xsaveSize, IsCETVmcsEnabled() ? 1U : 0U,
             IsXsavesEnabled() ? 1U : 0U);

    return true;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    HV_PASSIVE_PRINT("[HV] Unloading...\n");
    StopHypervisor();
    // The VMM owns the per-CPU VMXOFF and teardown-quiescence proof.  Do not
    // infer safety from a state enum or let an incomplete stop return to the
    // I/O manager, which may unmap this image immediately afterward.
    if (!IsHypervisorStopComplete() || IsHypervisorQuarantined()) {
        // unload has no failure return, so live VMX state must fail-stop before
        // control can return to the I/O manager and unmap this image
        KeBugCheckEx(kHvFatalBugCheck,
                     kHvFatalUnloadIncomplete,
                     IsHypervisorQuarantined() ? 1ULL : 0ULL,
                     reinterpret_cast<ULONG_PTR>(DriverObject),
                     0);
    }

    // UnregisterSecondaryDumpCallback fail-stops when the kernel refuses to
    // remove the callback.  The postcondition check below protects this
    // caller if that contract ever regresses or a quarantine is published
    // concurrently.
    UnregisterSecondaryDumpCallback();
    if (!IsHypervisorStopComplete() || IsHypervisorQuarantined()) {
        KeBugCheckEx(kHvFatalBugCheck,
                     kHvFatalUnloadCallbackState,
                     IsHypervisorQuarantined() ? 1ULL : 0ULL,
                     reinterpret_cast<ULONG_PTR>(DriverObject),
                     0);
    }
    HV_PASSIVE_PRINT("[HV] Stopped.\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    g_HvDriverObject = DriverObject;

    HV_PASSIVE_PRINT("[HV] Driver Entry. contract=%s\n", kDriverContractTag);

    if (!IsVmxSupported()) {
        HV_PASSIVE_PRINT("[HV] VMX capability gate rejected; see the preceding reason.\n");
        return STATUS_NOT_SUPPORTED;
    }

#ifndef USE_KDMAPPER
    DriverObject->DriverUnload = DriverUnload;
#endif

    // Register before the VMX transaction starts so a failure during prepare
    // or launch can still be exported through secondary dump data.
    if (!RegisterSecondaryDumpCallback()) {
        HV_PASSIVE_PRINT("[HV] Secondary dump callback registration failed; continuing without it\n");
    }

    NTSTATUS status = StartHypervisor();
    if (!NT_SUCCESS(status)) {
        HV_PASSIVE_PRINT("[HV] Failed to start: 0x%X\n", status);
        StopHypervisor();
        if (IsHypervisorQuarantined()) {
            DriverObject->DriverUnload = nullptr;
            HV_PASSIVE_PRINT("[HV] Start failure quarantined; driver remains resident\n");
            return STATUS_SUCCESS;
        }
        if (!IsHypervisorStopComplete()) {
            KeBugCheckEx(kHvFatalBugCheck,
                         kHvFatalUnloadIncomplete,
                         0,
                         reinterpret_cast<ULONG_PTR>(DriverObject),
                         static_cast<ULONG_PTR>(status));
        }
        UnregisterSecondaryDumpCallback();
        if (!IsHypervisorStopComplete() || IsHypervisorQuarantined()) {
            KeBugCheckEx(kHvFatalBugCheck,
                         kHvFatalUnloadCallbackState,
                         IsHypervisorQuarantined() ? 1ULL : 0ULL,
                         reinterpret_cast<ULONG_PTR>(DriverObject),
                         static_cast<ULONG_PTR>(status));
        }
        return status;
    }

    if (IsHypervisorQuarantined()) {
        DriverObject->DriverUnload = nullptr;
        HV_PASSIVE_PRINT("[HV] Start timed out; driver remains resident in quarantine\n");
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}
