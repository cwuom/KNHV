//
// Created by cwuom on 17 Feb 2026.
//

#include <intrin.h>
#include <ntddk.h>

#include "header/common.h"
#include "header/vmm.h"
#include "header/vmx.h"

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
                         u64* interruptSspTable) {
    if (!userCet || !supervisorCet || !xss || !pl0Ssp || !pl1Ssp ||
        !pl2Ssp || !pl3Ssp || !interruptSspTable) {
        return false;
    }

    __try {
        *userCet = __readmsr(MSR_IA32_U_CET);
        *supervisorCet = __readmsr(MSR_IA32_S_CET);
        *xss = __readmsr(MSR_IA32_XSS);
        *pl0Ssp = __readmsr(MSR_IA32_PL0_SSP);
        *pl1Ssp = __readmsr(MSR_IA32_PL1_SSP);
        *pl2Ssp = __readmsr(MSR_IA32_PL2_SSP);
        *pl3Ssp = __readmsr(MSR_IA32_PL3_SSP);
        *interruptSspTable = __readmsr(MSR_IA32_INTERRUPT_SSP_TABLE);
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
    if (maxBasicLeaf < 1) return RejectVmx("CPUID basic leaf 1 is unavailable");

    __cpuidex(cpuInfo, 1, 0);
    DbgPrint("[HV] CPUID.1:ECX=0x%08X\n", static_cast<ULONG>(cpuInfo[2]));
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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return RejectVmx("reading XCR0 faulted");
    }

    if (!ReadCETState(&userCet, &supervisorCet, &xss,
                      &pl0Ssp, &pl1Ssp, &pl2Ssp, &pl3Ssp,
                      &interruptSspTable)) {
        return RejectVmx("reading CET/XSS MSRs faulted");
    }
    DbgPrint("[HV] CET: IA32_U_CET=0x%llX IA32_S_CET=0x%llX "
             "IA32_XSS=0x%llX\n",
             userCet, supervisorCet, xss);
    DbgPrint("[HV] CET SSP: PL0=0x%llX PL1=0x%llX PL2=0x%llX "
             "PL3=0x%llX IST=0x%llX\n",
             pl0Ssp, pl1Ssp, pl2Ssp, pl3Ssp, interruptSspTable);

    // CR4.CET is set by Windows on CET-capable systems even when supervisor
    // enforcement is disabled.  The runtime contract enables the VMCS CET
    // fields and XSAVES path when needed, and rejects only combinations that
    // cannot be preserved by the fixed VM-exit frame.
    if (!InitializeVmxFeatureContract()) {
        return RejectVmx("CET/XSAVES state cannot be preserved on this processor");
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
        if (!(featureControl & IA32_FEATURE_CONTROL_LOCK)) {
            return RejectVmx("IA32_FEATURE_CONTROL is not locked");
        }
        if ((featureControl & (IA32_FEATURE_CONTROL_LOCK |
                               IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX)) !=
            (IA32_FEATURE_CONTROL_LOCK |
             IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX)) {
            return RejectVmx("VMXON outside SMX is disabled by IA32_FEATURE_CONTROL");
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

    int xsaveInfo[4] = {};
    // The compacted XSAVES frame is larger than the ordinary XCR0 frame on
    // CET-capable systems. Use leaf D.1:EBX when that contract is active.
    __cpuidex(xsaveInfo, 0xD, IsXsavesEnabled() ? 1 : 0);
    u32 xsaveSize = static_cast<u32>(xsaveInfo[1]);
    // HvVmExitEntryPoint reserves the first 0x1000 bytes of its frame for the
    // ordinary XSAVE area; the GPR/GuestContext fields begin at that exact
    // offset. A larger area would overwrite the saved registers and corrupt
    // the VM-exit continuation.
    if (xsaveSize > VMEXIT_XSAVE_MAX ||
        xsaveSize > sizeof(GuestContext{}.FxArea)) {
        return RejectVmx("XSAVE area exceeds the VM-exit frame");
    }

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
