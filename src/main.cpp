//
// Created by cwuom on 17 Feb 2026.
//

#include <intrin.h>
#include <ntddk.h>

#include "header/common.h"
#include "header/vmm.h"
#include "header/vmx.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject = nullptr;

static bool RejectVmx(const char* reason) {
    DbgPrint("[HV] VMX gate rejected: %s\n", reason);
    return false;
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
    DbgPrint("[HV] CPUID.0: max_basic=0x%X vendor=%08X-%08X-%08X\n",
             maxBasicLeaf, static_cast<ULONG>(cpuInfo[1]),
             static_cast<ULONG>(cpuInfo[3]), static_cast<ULONG>(cpuInfo[2]));
    if (maxBasicLeaf < 1) return RejectVmx("CPUID basic leaf 1 is unavailable");

    __cpuidex(cpuInfo, 1, 0);
    DbgPrint("[HV] CPUID.1:ECX=0x%08X\n", static_cast<ULONG>(cpuInfo[2]));
    DbgPrint("[HV] CPUID.1: VMX=%u XSAVE=%u OSXSAVE=%u hypervisor=%u CET_CR4=%u\n",
             (cpuInfo[2] & (1 << 5)) != 0 ? 1U : 0U,
             (cpuInfo[2] & (1 << 26)) != 0 ? 1U : 0U,
             (cpuInfo[2] & (1 << 27)) != 0 ? 1U : 0U,
             (cpuInfo[2] & (1 << 31)) != 0 ? 1U : 0U,
             (__readcr4() & CR4_CET) != 0 ? 1U : 0U);
    if (!(cpuInfo[2] & (1 << 5))) return RejectVmx("CPUID.1:ECX.VMX is clear");
    if (cpuInfo[2] & (1 << 31)) return RejectVmx("another hypervisor is active; nested VMX is disabled");
    if (!(cpuInfo[2] & (1 << 26)) || !(cpuInfo[2] & (1 << 27))) {
        return RejectVmx("XSAVE or OSXSAVE is unavailable");
    }
    // The VM-exit entry stub executes XGETBV/XSAVE/XRSTOR on every exit.  Do
    // not enter VMX unless the running kernel has enabled OSXSAVE and XCR0
    // contains the architectural x87 state required by XSAVE.
    const u64 currentCr4 = __readcr4();
    // CR4.CET is a prerequisite for CET, but it is not by itself proof that
    // shadow-stack or IBT enforcement is enabled. Those controls live in
    // IA32_{U,S}_CET, while IA32_XSS advertises supervisor XSTATE components
    // that ordinary XSAVE/XRSTOR does not preserve. Read the complete state
    // before deciding which capability is outside this monitor's contract.
    DbgPrint("[HV] CR4=0x%llX\n", currentCr4);
    if ((currentCr4 & (1ULL << 18)) == 0) return RejectVmx("CR4.OSXSAVE is clear");
    const u64 currentCr0 = __readcr0();
    DbgPrint("[HV] CR0=0x%llX\n", currentCr0);
    // XSAVE(S)/XRSTOR(S) raise #NM while CR0.TS is set and #UD while EM is
    // set. The VM-exit entry stub cannot safely take either fault, so reject a
    // nonstandard lazy-FPU configuration before VMXON instead of risking a
    // fault on the private VMX stack.
    if ((currentCr0 & ((1ULL << 2) | (1ULL << 3))) != 0) {
        return RejectVmx("CR0.EM or CR0.TS blocks XSAVE instructions");
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
        // XSAVE/XRSTOR and compiler-generated floating-point code require
        // both the architectural x87 and SSE state components enabled in
        // XCR0.  Refuse a nonstandard kernel configuration rather than
        // entering VMX with an XSAVE frame the exit stub cannot restore.
        const u64 xcr0 = _xgetbv(0);
        DbgPrint("[HV] XCR0=0x%llX\n", xcr0);
        if ((xcr0 & 0x3ULL) != 0x3ULL) return RejectVmx("XCR0 lacks x87/SSE state");
        __cpuidex(cpuInfo, 0xD, 0);
        const u64 supportedXcr0 = static_cast<u32>(cpuInfo[0]) |
                                  (static_cast<u64>(static_cast<u32>(cpuInfo[3])) << 32);
        if ((xcr0 & ~supportedXcr0) != 0) {
            return RejectVmx("XCR0 contains an unenumerated state component");
        }
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
        cetShadowStackEnumerated = (cpuInfo[2] & (1 << 7)) != 0;
        cetEnumerated = cetShadowStackEnumerated ||
                        (cpuInfo[3] & (1 << 20)) != 0;
        DbgPrint("[HV] CPUID.7.0: EBX=0x%08X ECX=0x%08X EDX=0x%08X "
                 "CET_SS=%u CET_IBT=%u PT=%u\n",
                 static_cast<ULONG>(cpuInfo[1]), static_cast<ULONG>(cpuInfo[2]),
                 static_cast<ULONG>(cpuInfo[3]), cetShadowStackEnumerated ? 1U : 0U,
                 (cpuInfo[3] & (1 << 20)) != 0 ? 1U : 0U,
                 (cpuInfo[1] & (1 << 25)) != 0 ? 1U : 0U);
    }
    bool xsavesEnumerated = false;
    bool xrstorsEnumerated = false;
    bool xfdEnumerated = false;
    if (maxBasicLeaf >= 0xD) {
        __cpuidex(cpuInfo, 0xD, 1);
        // Intel defines EAX[3] as the paired XSAVES/XRSTORS capability.
        // EAX[4] is extended feature disable (XFD), not XRSTORS.
        xsavesEnumerated = (cpuInfo[0] & CPUID_D1_XSAVES) != 0;
        xrstorsEnumerated = xsavesEnumerated;
        xfdEnumerated = (cpuInfo[0] & CPUID_D1_XFD) != 0;
        DbgPrint("[HV] CPUID.0D.1: EAX=0x%08X EBX=%u ECX=0x%08X EDX=0x%08X "
                 "XSAVES=%u XRSTORS=%u XFD=%u\n",
                 static_cast<ULONG>(cpuInfo[0]), static_cast<ULONG>(cpuInfo[1]),
                 static_cast<ULONG>(cpuInfo[2]), static_cast<ULONG>(cpuInfo[3]),
                 xsavesEnumerated ? 1U : 0U, xrstorsEnumerated ? 1U : 0U,
                 xfdEnumerated ? 1U : 0U);
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
    DbgPrint("[HV] CET: IA32_U_CET=0x%llX IA32_S_CET=0x%llX "
             "IA32_XSS=0x%llX\n",
             userCet, supervisorCet, xss);
    DbgPrint("[HV] CET SSP: PL0=0x%llX PL1=0x%llX PL2=0x%llX "
             "PL3=0x%llX IST=0x%llX\n",
             pl0Ssp, pl1Ssp, pl2Ssp, pl3Ssp, interruptSspTable);

    if (!InitializeVmxFeatureContract()) {
        return RejectVmx("XSAVE/CET state cannot be preserved on this processor");
    }

    // Windows 11 25H2 commonly leaves CR4.CET set while supervisor shadow
    // stacks are inactive.  The monitor can preserve CET_U through XSAVES and
    // the supervisor VMCS fields, but it deliberately does not implement an
    // active supervisor shadow stack or an interrupt SSP table.
    if ((supervisorCet & IA32_CET_ENABLE_MASK) != 0 ||
        supervisorCet != 0 || pl0Ssp != 0 || pl1Ssp != 0 ||
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
    DbgPrint("[HV] CET contract selected: VMCS=%u XSAVES=%u\n",
             IsCETVmcsEnabled() ? 1U : 0U,
             IsXsavesEnabled() ? 1U : 0U);
    if (maxBasicLeaf < 0xD) return RejectVmx("CPUID leaf 0xD is unavailable");

    __try {
        u64 featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);
        // Do not write IA32_FEATURE_CONTROL here.  Setting the lock bit is
        // irreversible until reset and can conflict with firmware, BitLocker,
        // or another type-1 monitor.  A driver that cannot prove VMXON is
        // already permitted must fail closed before allocating VMX state.
        DbgPrint("[HV] IA32_FEATURE_CONTROL=0x%llX\n", featureControl);
        if ((featureControl & IA32_FEATURE_CONTROL_LOCK) != 0 &&
            (featureControl & IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX) == 0) {
            return RejectVmx("VMXON outside SMX is disabled by IA32_FEATURE_CONTROL");
        }
        if ((featureControl & IA32_FEATURE_CONTROL_LOCK) == 0) {
            DbgPrint("[HV] IA32_FEATURE_CONTROL is unlocked; each CPU will "
                     "provision LOCK|VMXON_OUTSIDE_SMX before VMXON\n");
        }

        const u64 vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
        DbgPrint("[HV] IA32_VMX_BASIC=0x%llX\n", vmxBasic);
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
    DbgPrint("[HV] VMX gate accepted: xsave_frame=%u cet_vmcs=%u xsaves=%u\n",
             xsaveSize, IsCETVmcsEnabled() ? 1U : 0U,
             IsXsavesEnabled() ? 1U : 0U);

    return true;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[HV] Unloading...\n");
    StopHypervisor();
    DbgPrint("[HV] Stopped.\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    g_HvDriverObject = DriverObject;

    DbgPrint("[HV] Driver Entry.\n");

    if (!IsVmxSupported()) {
        DbgPrint("[HV] VMX not supported or disabled in BIOS.\n");
        return STATUS_NOT_SUPPORTED;
    }

#ifndef USE_KDMAPPER
    DriverObject->DriverUnload = DriverUnload;
#endif

    NTSTATUS status = StartHypervisor();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] Failed to start: 0x%X\n", status);
        StopHypervisor();
        return status;
    }

    DbgPrint("[HV] VMX monitor started on all active processors.\n");
    return STATUS_SUCCESS;
}
