// capability discovery and immutable host-state contract
// capability checks are isolated here so the launch path only consumes a
// stable, immutable contract

#include "vmm_internal.h"

extern "C" PDRIVER_OBJECT g_HvDriverObject;
// VMX capability MSRs expose mandatory-one bits in the low half and optional
// allowed-one bits in the high half. Either half can make a requested one
// architecturally valid.
bool ControlBitCanBeOne(u64 capability, u32 mask) {
    const u32 mandatoryOne = static_cast<u32>(capability);
    const u32 allowedOne = static_cast<u32>(capability >> 32);
    return ((mandatoryOne | allowedOne) & mask) == mask;
}

u32 BuildVmxCapabilityProfile(u64 vmxBasic, bool xsaves,
                                     bool cetVmcs) {
    u32 profile = (vmxBasic & VMX_BASIC_TRUE_CONTROLS) != 0
                      ? VmxProfileTrueControls
                      : VmxProfileLegacyControls;
    const u32 primaryMsr = ControlMsr(vmxBasic,
                                      MSR_IA32_VMX_PROCBASED_CTLS,
                                      MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    u64 primaryControls = 0;
    const bool primaryRead = ReadMsrSafe(primaryMsr, &primaryControls);
    u64 secondaryControls = 0;
    const bool secondaryField =
        primaryRead &&
        ControlBitCanBeOne(primaryControls,
                           CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) &&
        ReadMsrSafe(MSR_IA32_VMX_PROCBASED_CTLS2, &secondaryControls);
    if (secondaryField) {
        profile |= VmxProfileSecondaryControls;
    }
    if (xsaves && secondaryField &&
        ControlBitCanBeOne(secondaryControls, SECONDARY_ENABLE_XSAVES)) {
        profile |= VmxProfileXsaves;
    }
    if (cetVmcs) profile |= VmxProfileCetVmcs;
    int regs[4] = {};
    __cpuid(regs, 0);
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);
    if (maxBasicLeaf >= 7) {
        __cpuidex(regs, 7, 0);
        if (secondaryField &&
            (regs[1] & (1 << 10)) != 0 &&
            ControlBitCanBeOne(secondaryControls, SECONDARY_ENABLE_INVPCID)) {
            profile |= VmxProfileInvpcid;
        }
    }
    __cpuidex(regs, 0x80000000, 0);
    const u32 maxExtendedLeaf = static_cast<u32>(regs[0]);
    if (maxExtendedLeaf >= 0x80000001) {
        __cpuidex(regs, 0x80000001, 0);
        if (secondaryField &&
            (regs[3] & (1 << 27)) != 0 &&
            ControlBitCanBeOne(secondaryControls, SECONDARY_ENABLE_RDTSCP)) {
            profile |= VmxProfileRdtscp;
        }
    }

    if (primaryRead &&
        ControlBitCanBeOne(primaryControls,
                           CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)) {
        u64 tertiaryControls = 0;
        if (ReadMsrSafe(MSR_IA32_VMX_PROCBASED_CTLS3, &tertiaryControls)) {
            profile |= VmxProfileTertiaryControls;
        }
    }
    return profile;
}

static IntelCpuBranch SelectIntelCpuBranch(u32 family, u32 model,
                                           u32 coreType, u32 profile) {
    // Keep the hybrid path allow-listed.  A future core type can share the
    // CPUID encoding while changing VMX capability details; fail closed until
    // that model has been audited instead of guessing from the core type.
    const bool knownHybridModel =
        family == 6U &&
        (model == 0x97U || model == 0x9AU || model == 0xB7U ||
         model == 0xBAU || model == 0xBFU);
    // Intel hybrid processors identify a performance core as 40h and an
    // efficient core as 20h in CPUID.1A. Keep those paths separate because
    // their VMX capability MSRs are sampled on the executing logical CPU.
    if (coreType == 0x40U) {
        return knownHybridModel ? IntelCpuBranchHybridPerformance
                                : IntelCpuBranchHybridUnknown;
    }
    if (coreType == 0x20U) {
        return knownHybridModel ? IntelCpuBranchHybridEfficient
                                : IntelCpuBranchHybridUnknown;
    }
    if (coreType != 0) return IntelCpuBranchHybridUnknown;

    // Family 6 model 0x97 is Alder Lake and 0xB7 is Raptor Lake.  The 14th
    // generation desktop parts use the same true-control VMX contract, but the
    // model test stays explicit so an unknown future model cannot silently use
    // a modern branch without a capability bit proving it safe.
    const bool knownModernModel = knownHybridModel;
    if (family != 6U) return IntelCpuBranchUnknown;
    if (knownModernModel &&
        (profile & VmxProfileTrueControls) != 0) {
        return IntelCpuBranchModern;
    }
    // Older family-6 parts use the legacy branch even when firmware exposes
    // true-control MSRs. Their optional controls are still selected from the
    // local capability profile, so this branch is not a guessed model table.
    return IntelCpuBranchLegacy;
}

IntelCpuIdentity QueryIntelCpuIdentity(u32 profile) {
    IntelCpuIdentity identity{};
    identity.Branch = IntelCpuBranchUnknown;

    int regs[4] = {};
    __cpuid(regs, 0);
    identity.GenuineIntel =
        static_cast<u32>(regs[1]) == 0x756E6547U &&
        static_cast<u32>(regs[3]) == 0x49656E69U &&
        static_cast<u32>(regs[2]) == 0x6C65746EU;
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);
    if (!identity.GenuineIntel || maxBasicLeaf < 1U) return identity;

    __cpuidex(regs, 1, 0);
    const u32 version = static_cast<u32>(regs[0]);
    const u32 baseFamily = (version >> 8) & 0xFU;
    const u32 baseModel = (version >> 4) & 0xFU;
    const u32 extendedFamily = (version >> 20) & 0xFFU;
    const u32 extendedModel = (version >> 16) & 0xFU;
    identity.Family = baseFamily == 0xFU
                          ? baseFamily + extendedFamily
                          : baseFamily;
    identity.Model = (baseFamily == 0x6U || baseFamily == 0xFU)
                         ? baseModel | (extendedModel << 4)
                         : baseModel;
    identity.Stepping = version & 0xFU;

    if (maxBasicLeaf >= 0x1AU) {
        __cpuidex(regs, 0x1A, 0);
        identity.CoreType = (static_cast<u32>(regs[0]) >> 24) & 0xFFU;
    }
    identity.Branch = SelectIntelCpuBranch(identity.Family, identity.Model,
                                           identity.CoreType, profile);
    return identity;
}

const char* IntelCpuBranchName(IntelCpuBranch branch) {
    switch (branch) {
        case IntelCpuBranchLegacy: return "legacy";
        case IntelCpuBranchModern: return "modern";
        case IntelCpuBranchHybridPerformance: return "hybrid-p";
        case IntelCpuBranchHybridEfficient: return "hybrid-e";
        case IntelCpuBranchHybridUnknown: return "hybrid-unknown";
        default: return "unknown";
    }
}

bool IsIntelCpuBranchCompatible(const IntelCpuIdentity& identity,
                                       u32 profile) {
    if (!identity.GenuineIntel || identity.Branch == IntelCpuBranchUnknown ||
        identity.Branch == IntelCpuBranchHybridUnknown) {
        return false;
    }

    const bool trueControls = (profile & VmxProfileTrueControls) != 0;
    const bool secondaryControls =
        (profile & VmxProfileSecondaryControls) != 0;
    switch (identity.Branch) {
        case IntelCpuBranchHybridPerformance:
        case IntelCpuBranchHybridEfficient:
            // The hybrid branches use the same architectural VMX fields, but
            // require the true/secondary capability path independently on each
            // P/E core before a VMCS is constructed.
            return trueControls && secondaryControls;
        case IntelCpuBranchModern:
            return trueControls;
        case IntelCpuBranchLegacy:
            return true;
        default:
            return false;
    }
}

// CPUID.0D.1:EBX describes only the state selected by the current XCR0 and
// IA32_XSS values.  The VM-exit frame instead uses one immutable XSAVES mask,
// so calculate the compacted size from every component in that mask.
bool ComputeXsaveAreaSize(u64 xcr0Mask, u64 xssMask,
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
        const u32 componentFlags = static_cast<u32>(regs[2]);
        const bool xssComponent = (componentFlags & 0x1U) != 0;
        const bool xcr0Component = !xssComponent;
        if (((xcr0Mask & bit) != 0 && !xcr0Component) ||
            ((xssMask & bit) != 0 && !xssComponent)) {
            return false;
        }
        // Intel's compacted XSAVE format aligns selected components when
        // CPUID.(D,n).ECX[1] requests the next 64-byte boundary
        if ((componentFlags & 0x2U) != 0) {
            offset = (offset + 63ULL) & ~63ULL;
        }
        offset += componentSize;
        if (offset > MAXULONG) return false;
    }

    *areaSize = static_cast<u32>(offset);
    return true;
}

    // cpuid.0d.0 reports the standard, non-compacted XSAVE layout. Keep this
    // separate from ComputeXsaveAreaSize because its EBX offsets are not valid
    // for the compacted XSAVES format used by the VM-exit frame
bool ComputeStandardXsaveAreaSize(u64 xcr0Mask, u32* areaSize) {
    if (!areaSize) return false;

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

    u64 size = 576;
    for (u32 component = 2; component < 64; ++component) {
        const u64 bit = 1ULL << component;
        if ((xcr0Mask & bit) == 0) continue;

        __cpuidex(regs, 0xD, static_cast<int>(component));
        const u32 componentSize = static_cast<u32>(regs[0]);
        const u32 componentOffset = static_cast<u32>(regs[1]);
        if (componentSize == 0 || componentOffset < 576) return false;

        const u64 end = static_cast<u64>(componentOffset) + componentSize;
        if (end > MAXULONG) return false;
        if (end > size) size = end;
    }

    *areaSize = static_cast<u32>(size);
    return true;
}

bool VmxControlAllows(u32 msr, u32 mask) {
    ULARGE_INTEGER value{};
    __try {
        value.QuadPart = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return ControlBitCanBeOne(value.QuadPart, mask);
}

bool ReadMsrSafe(u32 msr, u64* value) {
    if (!value) return false;
    __try {
        *value = __readmsr(msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool WriteMsrSafe(u32 msr, u64 value) {
    __try {
        __writemsr(msr, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool EnsureFeatureControlForVmx() {
    u64 featureControl = 0;
    if (!ReadMsrSafe(MSR_IA32_FEATURE_CONTROL, &featureControl)) return false;
    const u64 required = IA32_FEATURE_CONTROL_LOCK |
                         IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX;
    // This MSR is package firmware policy and the lock bit is irreversible
    // until reset. A late-launch driver must never claim it on behalf of the
    // platform; an unlocked or incomplete policy is rejected before VMXON.
    return (featureControl & required) == required;
}

bool IsIntelPtMsr(u32 msr) {
    // pt has reserved holes, so keep the complete architectural window together
    return msr >= MSR_IA32_RTIT_OUTPUT_BASE && msr <= 0x58FU;
}

bool IsCetStateMsr(u32 msr) {
    return msr == MSR_IA32_U_CET || msr == MSR_IA32_S_CET ||
           msr == MSR_IA32_PL0_SSP || msr == MSR_IA32_PL1_SSP ||
           msr == MSR_IA32_PL2_SSP || msr == MSR_IA32_PL3_SSP ||
           msr == MSR_IA32_INTERRUPT_SSP_TABLE;
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

bool IsGdtSelectorUsable(u64 gdtBase, u16 gdtLimit, u16 selector,
                                bool allowNull, bool requireSystem,
                                bool requireCode,
                                bool requireKernelPrivilege,
                                bool requireWritableData) {
    if (selector == 0) return allowNull;
    const u16 offset = selector & 0xFFF8U;
    // segment RPL may be nonzero for the current DS, ES, FS, or GS selector
    // even while the kernel runs at CPL 0. Only LDT selectors lack a GDT base.
    if ((selector & 0x4U) != 0 || offset > gdtLimit ||
        gdtLimit - offset < 7U ||
        !IsCanonical(gdtBase) || !IsCanonical(gdtBase + offset)) {
        return false;
    }
    const auto descriptor = reinterpret_cast<const u8*>(gdtBase + offset);
    const u8 access = descriptor[5];
    const u8 type = access & 0x0FU;
    if ((access & 0x80U) == 0) return false;
    if (requireKernelPrivilege &&
        (((selector & 0x3U) != 0) || (access & 0x60U) != 0)) {
        return false;
    }
    if (requireSystem) {
        return (access & 0x10U) == 0 && (type == 9U || type == 0xBU) &&
               gdtLimit - offset >= 15U;
    }
    if ((access & 0x10U) == 0) return false;

    // Intel VM-entry checks require the accessed bit for every usable
    // CS/SS/DS/ES/FS/GS descriptor. CS must be accessed code; SS must be
    // writable accessed data. DS/ES/FS/GS may legally reference readable
    // accessed code, so executable selectors are not rejected categorically.
    if (requireCode) {
        return (type & 0x9U) == 0x9U;
    }
    if (requireWritableData) {
        return (type & 0x8U) == 0 && (type & 0x3U) == 0x3U;
    }

    // For DS/ES/FS/GS, Intel allows accessed data and readable accessed code.
    // Non-conforming code/data (types 0..11) also requires DPL >= selector RPL.
    const u8 dpl = static_cast<u8>((access >> 5) & 0x3U);
    const u8 rpl = static_cast<u8>(selector & 0x3U);
    if (type <= 0xBU && dpl < rpl) return false;
    if ((type & 0x8U) != 0) {
        return (type & 0xBU) == 0xBU;
    }
    return (type & 0x1U) != 0;
}

bool IsGuestTrSelectorUsable(u64 gdtBase, u16 gdtLimit,
                                    u16 selector) {
    if (!IsGdtSelectorUsable(gdtBase, gdtLimit, selector, false, true, false,
                             true, false)) {
        return false;
    }
    const u16 offset = selector & 0xFFF8U;
    const auto descriptor = reinterpret_cast<const u8*>(gdtBase + offset);
    const u8 type = descriptor[5] & 0x0FU;
    // ia-32e guest state requires a present busy 64-bit tss descriptor. an
    // available tss would make vmlaunch fail with invalid guest state
    return type == 0xBU;
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
        g_XstateMode = XstateSaveFxsave;
        g_XsavesMask = 0;
        g_EnumeratedXssMask = 0;
        g_SupportedXssMask = 0;
        g_GuestXssWriteMask = 0;
        g_HostXssMask = 0;
        g_HostXcr0Mask = 0;
        g_DebugctlMask = kDebugctlArchitecturalMask;
        g_XsaveStateSize = 0;
        g_VmxCapabilityProfile = 0;
        InterlockedExchange(&g_VmxGuestOptionalProfile, 0);
        InterlockedExchange(&g_VmxGuestOptionalProfileCandidate, 0);
    }
    if (g_VmxFeatureContractInitialized) {
        return g_VmxFeatureContractValid;
    }
    g_VmxFeatureContractInitialized = true;
    g_VmxFeatureContractValid = false;
    g_CetVmcsEnabled = 0;
    g_XsavesEnabled = 0;
    g_XstateMode = XstateSaveFxsave;
    g_XsavesMask = 0;
    g_EnumeratedXssMask = 0;
    g_SupportedXssMask = 0;
    g_GuestXssWriteMask = 0;
    g_HostXssMask = 0;
    g_HostXcr0Mask = 0;
    g_DebugctlMask = GetDebugctlCapabilityMask();
    g_XsaveStateSize = 0;
    g_VmxCapabilityProfile = 0;
    InterlockedExchange(&g_VmxGuestOptionalProfile, 0);
    InterlockedExchange(&g_VmxGuestOptionalProfileCandidate, 0);

    int regs[4] = {};
    __cpuid(regs, 0);
    const u32 maxBasicLeaf = static_cast<u32>(regs[0]);

    u64 vmxBasic = 0;
    if (!ReadMsrSafe(MSR_IA32_VMX_BASIC, &vmxBasic)) return false;
    const u64 currentCr4 = __readcr4();
    int leaf1[4] = {};
    __cpuidex(leaf1, 1, 0);
    const bool xsaveEnumerated =
        (static_cast<u32>(leaf1[2]) & CPUID_1_ECX_XSAVE) != 0;
    const bool osxsaveEnabled =
        (static_cast<u32>(leaf1[2]) & CPUID_1_ECX_OSXSAVE) != 0;
    const bool cr4OsxsaveEnabled = (currentCr4 & CR4_OSXSAVE) != 0;
    const bool fxsrEnumerated =
        (static_cast<u32>(leaf1[3]) & CPUID_1_EDX_FXSR) != 0;

    // Keep a real legacy backend for old VMX processors. It saves only the
    // architectural FPU/SSE image and never executes XGETBV or IA32_XSS.
    if (maxBasicLeaf < 0xD || !xsaveEnumerated || !osxsaveEnabled ||
        !cr4OsxsaveEnabled) {
        if (!fxsrEnumerated || (currentCr4 & CR4_OSFXSR) == 0 ||
            (currentCr4 & CR4_OSXSAVE) != 0 ||
            (currentCr4 & CR4_CET) != 0 ||
            (currentCr4 & CR4_FRED) != 0 ||
            (currentCr4 & CR4_PKE) != 0) {
            return false;
        }
        g_XstateMode = XstateSaveFxsave;
        g_XsavesEnabled = 0;
        g_XsavesMask = 0;
        g_EnumeratedXssMask = 0;
        g_SupportedXssMask = 0;
        g_GuestXssWriteMask = 0;
        g_HostXssMask = 0;
        g_HostXcr0Mask = 0;
        g_XsaveStateSize = FXSAVE_AREA_SIZE;
        g_VmxCapabilityProfile = BuildVmxCapabilityProfile(vmxBasic, false, false);
        g_VmxFeatureContractValid = true;
        return true;
    }

    g_VmxCapabilityProfile = BuildVmxCapabilityProfile(vmxBasic, false, false);

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
    if ((currentCr4 & CR4_PKE) != 0 && (hostXcr0 & XCR0_PKRU) == 0) {
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
    // a late launch must preserve every supervisor component selected by Windows
    if ((hostXss & ~IA32_XSS_PRESERVABLE_MASK) != 0) {
        return false;
    }

    KNHV_PASSIVE_PRINT("[KNHV] XSTATE contract: XSAVES=%u XRSTORS=%u XFD=%u D1.EBX=%lu "
             "XSS_ENUM=0x%llX HOST_XSS=0x%llX\n",
             xsavesInstruction ? 1U : 0U,
             xrstorsInstruction ? 1U : 0U,
             xfdInstruction ? 1U : 0U,
             static_cast<ULONG>(xsavesSize), enumeratedXss, hostXss);
    if (xsavesInstruction != xrstorsInstruction) return false;

    // an IPT XSS component can remain selected after VMXON only when this CPU
    // advertises PT support in VMX operation. The guest PT surface stays hidden.
    if ((hostXss & IA32_XSS_IPT) != 0) {
        u64 vmxMisc = 0;
        u64 ptControl = 0;
        if (!ReadMsrSafe(MSR_IA32_VMX_MISC, &vmxMisc) ||
            !ReadMsrSafe(MSR_IA32_RTIT_CTL, &ptControl)) {
            KNHV_PASSIVE_PRINT("[KNHV] Intel PT/XSS gate rejected: capability read failed\n");
            return false;
        }
        if ((vmxMisc & VMX_MISC_INTEL_PT) == 0) {
            KNHV_PASSIVE_PRINT("[KNHV] Intel PT/XSS gate rejected: VMX_MISC lacks post-VMXON PT\n");
            return false;
        }
        if ((ptControl & IA32_RTIT_CTL_TRACEEN) != 0) {
            KNHV_PASSIVE_PRINT("[KNHV] Intel PT/XSS gate rejected: tracing is active\n");
            return false;
        }
    }

    // the host selector is sampled independently from the immutable frame
    // contract. a guest may change its virtual selector without changing the
    // XSAVES layout used by the VM-exit assembly
    g_HostXssMask = hostXss;
    g_HostXcr0Mask = hostXcr0;

    const bool secondaryControlsUsable =
        (g_VmxCapabilityProfile & VmxProfileSecondaryControls) != 0;
    if (xsavesInstruction && xssRead && secondaryControlsUsable &&
        VmxControlAllows(MSR_IA32_VMX_PROCBASED_CTLS2,
                          SECONDARY_ENABLE_XSAVES)) {
        // late launch begins with the live Windows selector, so the fixed frame
        // must preserve every selected component rather than the guest policy
        const u64 fixedXssMask = hostXss;
        if ((fixedXssMask & ~enumeratedXss) != 0 ||
            (fixedXssMask & ~IA32_XSS_PRESERVABLE_MASK) != 0) {
            return false;
        }

        u64 computedXssCapabilities = 0;
        if (!ComputeXsaveAreaSize(hostXcr0, fixedXssMask,
                                   &computedXssCapabilities,
                                   &g_XsaveStateSize) ||
            (fixedXssMask & ~computedXssCapabilities) != 0 ||
            g_XsaveStateSize != xsavesSize) {
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
        g_XstateMode = XstateSaveXsave;
        g_SupportedXssMask = 0;
    } else {
        g_XstateMode = XstateSaveXsaves;
    }

    // the frame mask is immutable for this VMX run and represents preservation,
    // not the current guest selector
    g_XsavesMask = g_XsavesEnabled
                        ? g_HostXssMask
                        : 0;
    // expose only supervisor components that the fixed frame can restore. this
    // includes the initial host selector, so CPUID and WRMSR share one contract
    g_SupportedXssMask =
        g_XsavesEnabled
            ? (g_XsavesMask & enumeratedXss & IA32_XSS_PRESERVABLE_MASK)
            : 0;
    g_GuestXssWriteMask = g_SupportedXssMask;

    if (g_XsaveStateSize == 0 || g_XsaveStateSize > VMEXIT_XSAVE_MAX) {
        return false;
    }

    KNHV_PASSIVE_PRINT("[KNHV] XSTATE preservation: XSAVES=%u HOST_XSS=0x%llX "
             "PRESERVE_XSS=0x%llX GUEST_INITIAL_XSS=0x%llX "
             "GUEST_WRITE_XSS=0x%llX frame=%lu D1.EBX=%lu\n",
             g_XsavesEnabled ? 1U : 0U,
             g_HostXssMask, g_XsavesMask, g_HostXssMask,
             g_GuestXssWriteMask, static_cast<ULONG>(g_XsaveStateSize),
             static_cast<ULONG>(xsavesSize));

    // CR4.CET is set on current Windows 11 builds even when supervisor CET
    // is inactive. In that state VMX still requires the paired CET entry/exit
    // controls and architecturally valid VMCS CET fields.
    if ((currentCr4 & CR4_CET) != 0) {
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

    g_VmxCapabilityProfile = BuildVmxCapabilityProfile(
        vmxBasic, g_XsavesEnabled != 0, g_CetVmcsEnabled != 0);

    KNHV_PASSIVE_PRINT("[KNHV] VMX control contract: profile=0x%X CET_VMCS=%u XSAVES=%u\n",
             g_VmxCapabilityProfile, g_CetVmcsEnabled ? 1U : 0U,
             g_XsavesEnabled ? 1U : 0U);

    g_VmxFeatureContractValid = true;
    return true;
}

// tags for memory allocation (avoid multi-char warnings by using integers)
