#include "nested_internal.h"

namespace knhv {
namespace nested_internal {
namespace {

constexpr u64 kMask16 = ~0xFFFFULL;
constexpr u64 kMask32 = ~0xFFFFFFFFULL;
constexpr u32 kPrimaryActivateSecondary = 1U << 31;

constexpr FieldRule kFieldRules[] = {
    {kVmcsFieldVpid, 2, 1, FieldControlNone, 0, kMask16, 0},
    {kVmcsFieldEptpIndex, 2, 1, FieldControlNone, 0, kMask16, 0},
    {kVmcsFieldIoBitmapA, 8, 1, FieldControlNone, 1, 0, 0},
    {kVmcsFieldIoBitmapB, 8, 1, FieldControlNone, 1, 0, 0},
    {kVmcsFieldMsrBitmap, 8, 1, FieldControlNone, 1, 0, 0},
    {kVmcsFieldEptPointer, 8, 1, FieldControlNone, 1, 0xFFFULL, 0},
    {kVmcsFieldVpidAddress, 8, 1, FieldControlNone, 1, 0xFFFULL, 0},
    {kVmcsFieldPinControls, 4, 1, FieldControlPin, 0, kMask32, 0},
    {kVmcsFieldPrimaryControls, 4, 1, FieldControlPrimary, 0, kMask32, 0},
    {kVmcsFieldExceptionBitmap, 4, 1, FieldControlNone, 0, kMask32, 0},
    {kVmcsFieldExitControls, 4, 1, FieldControlExit, 0, kMask32, 0},
    {kVmcsFieldEntryControls, 4, 1, FieldControlEntry, 0, kMask32, 0},
    {kVmcsFieldSecondaryControls, 4, 1, FieldControlSecondary, 0, kMask32,
     0},
    {kVmcsFieldInstructionError, 4, 0, FieldControlNone, 0, kMask32, 0},
    {kVmcsFieldExitReason, 4, 0, FieldControlNone, 0, kMask32, 0},
    {kVmcsFieldExitQualification, 8, 0, FieldControlNone, 0, 0, 0},
    {kVmcsFieldGuestCr0, 8, 1, FieldControlNone, 2, 0, 0},
    {kVmcsFieldGuestCr3, 8, 1, FieldControlNone, 2, 0, 0},
    {kVmcsFieldGuestCr4, 8, 1, FieldControlNone, 2, 0, 0},
    {kVmcsFieldGuestRsp, 8, 1, FieldControlNone, 2, 0, 0},
    {kVmcsFieldGuestRip, 8, 1, FieldControlNone, 2, 0, 0},
    {kVmcsFieldGuestRflags, 8, 1, FieldControlNone, 2, 0, 0},
    {kVmcsFieldHostCr0, 8, 1, FieldControlNone, 3, 0, 0},
    {kVmcsFieldHostCr3, 8, 1, FieldControlNone, 3, 0, 0},
    {kVmcsFieldHostCr4, 8, 1, FieldControlNone, 3, 0, 0},
    {kVmcsFieldHostRsp, 8, 1, FieldControlNone, 3, 0, 0},
    {kVmcsFieldHostRip, 8, 1, FieldControlNone, 3, 0, 0},
    {0x2800U, 8, 1, FieldControlNone, 1, 0, 0},
    {0x2802U, 8, 1, FieldControlNone, 1, 0, 0},
    {0x2804U, 8, 1, FieldControlNone, 1, 0, 0},
    {0x2806U, 8, 1, FieldControlNone, 1, 0, 0},
    {0x2808U, 8, 1, FieldControlNone, 1, 0, 0},
    {0x4006U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4008U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x400AU, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4014U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4016U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4018U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x401AU, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x401CU, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4404U, 4, 0, FieldControlNone, 0, kMask32, 0},
    {0x4406U, 4, 0, FieldControlNone, 0, kMask32, 0},
    {0x4408U, 4, 0, FieldControlNone, 0, kMask32, 0},
    {0x440AU, 4, 0, FieldControlNone, 0, kMask32, 0},
    {0x440CU, 4, 0, FieldControlNone, 0, kMask32, 0},
    {0x440EU, 4, 0, FieldControlNone, 0, kMask32, 0},
    {0x4800U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4802U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4804U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4806U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4808U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x480AU, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4824U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x4826U, 4, 1, FieldControlNone, 0, kMask32, 0},
    {0x6806U, 8, 1, FieldControlNone, 2, 0, 0},
    {0x6808U, 8, 1, FieldControlNone, 2, 0, 0},
    {0x680AU, 8, 1, FieldControlNone, 2, 0, 0},
    {0x680CU, 8, 1, FieldControlNone, 2, 0, 0},
    {0x680EU, 8, 1, FieldControlNone, 2, 0, 0},
    {0x6810U, 8, 1, FieldControlNone, 2, 0, 0},
    {0x681AU, 8, 1, FieldControlNone, 2, 0, 0},
    {0x6822U, 8, 1, FieldControlNone, 2, 0, 0},
};

constexpr u32 kFieldRuleCount =
    static_cast<u32>(sizeof(kFieldRules) / sizeof(kFieldRules[0]));

u64 FieldMask(u8 width) {
    if (width == 2) return 0xFFFFULL;
    if (width == 4) return 0xFFFFFFFFULL;
    return ~0ULL;
}

u64 ReadStoredField(const NestedVmcs12& vmcs, const FieldRule& rule) {
    return vmcs.fields[FieldIndex(&rule)];
}

void WriteStoredField(NestedVmcs12& vmcs, const FieldRule& rule, u64 value) {
    vmcs.fields[FieldIndex(&rule)] = value & FieldMask(rule.width);
    vmcs.dirty_groups |= 1ULL << (rule.clean_group & 63U);
}

bool IsFixedCrValid(u64 value, u64 fixed0, u64 fixed1) {
    if ((value & fixed0) != fixed0) return false;
    if (fixed1 != 0 && (value & ~fixed1) != 0) return false;
    return true;
}

}  // namespace

const FieldRule* FindFieldRule(u32 encoding) {
    for (u32 index = 0; index < kFieldRuleCount; ++index) {
        if (kFieldRules[index].encoding == encoding) {
            return &kFieldRules[index];
        }
    }
    return nullptr;
}

u32 FieldIndex(const FieldRule* rule) {
    if (rule == nullptr) return kNestedVmcsFields;
    const u32 index = static_cast<u32>(rule - kFieldRules);
    return index < kNestedVmcsFields ? index : kNestedVmcsFields;
}

bool IsCanonicalAddress(u64 value, u32 address_bits) {
    const u32 bits = address_bits >= 48U && address_bits <= 63U
                         ? address_bits
                         : 48U;
    const u64 low_mask = (1ULL << bits) - 1ULL;
    const u64 sign_bit = 1ULL << (bits - 1U);
    const u64 upper = value & ~low_mask;
    return (value & sign_bit) == 0 ? upper == 0 : upper == ~low_mask;
}

bool IsLinearRangeCanonical(const NestedVcpu* vcpu, u64 linear, u32 length) {
    if (vcpu == nullptr || length == 0) return false;
    const u64 last = static_cast<u64>(length - 1U);
    if (linear > ~0ULL - last) return false;
    return IsCanonicalAddress(linear,
                              vcpu->capabilities.linear_address_bits) &&
           IsCanonicalAddress(linear + last,
                              vcpu->capabilities.linear_address_bits);
}

bool IsPhysicalAddress(u64 value, u32 address_bits) {
    const u32 bits = address_bits >= 1U && address_bits <= 52U
                         ? address_bits
                         : 48U;
    return (value >> bits) == 0;
}

bool IsAlignedPage(u64 value) {
    return (value & (static_cast<u64>(kNestedPageSize) - 1ULL)) == 0;
}

NestedResult MakeResult(HvStatus status, NestedAction action,
                        u32 instruction_error, u32 instruction_length,
                        u64 rflags, u64 value) {
    NestedResult result = {};
    result.status = status;
    result.action = action;
    result.instruction_error = instruction_error;
    result.instruction_length = instruction_length;
    result.rflags = rflags;
    result.value = value;
    return result;
}

NestedResult MakeSuccess(NestedAction action, u32 instruction_length,
                         u64 value) {
    return MakeResult(HvStatus::Success, action, 0U, instruction_length, 0,
                      value);
}

void ClearVmInstructionError(NestedVcpu* vcpu) {
    if (vcpu == nullptr) return;
    vcpu->instruction_error = 0;
    NestedVmcs12* current = CurrentVmcs(vcpu);
    if (current != nullptr) SetVmcsReadOnly(current, kVmcsFieldInstructionError,
                                            0);
}

NestedResult MakeVmfail(NestedVcpu* vcpu, HvStatus status,
                        u32 instruction_error, u32 instruction_length) {
    const bool valid = status == HvStatus::VmfailValid;
    if (vcpu != nullptr && valid) {
        vcpu->instruction_error = instruction_error;
        NestedVmcs12* current = CurrentVmcs(vcpu);
        if (current != nullptr) {
            SetVmcsReadOnly(current, kVmcsFieldInstructionError,
                            instruction_error);
        }
    }
    const u64 rflags = valid ? kRflagsZero : kRflagsCarry;
    const u32 visible_error = valid ? instruction_error : 0U;
    return MakeResult(status, NestedAction::ResumeL1, visible_error,
                      instruction_length, rflags, 0);
}

NestedVmcs12* FindVmcs(NestedVcpu* vcpu, u64 region_gpa) {
    if (vcpu == nullptr) return nullptr;
    for (u32 index = 0; index < kNestedVmcsSlots; ++index) {
        NestedVmcs12* vmcs = &vcpu->vmcs[index];
        if (vmcs->allocated != 0 && vmcs->region_gpa == region_gpa) {
            return vmcs;
        }
    }
    return nullptr;
}

const NestedVmcs12* FindVmcs(const NestedVcpu* vcpu, u64 region_gpa) {
    return FindVmcs(const_cast<NestedVcpu*>(vcpu), region_gpa);
}

NestedVmcs12* CurrentVmcs(NestedVcpu* vcpu) {
    if (vcpu == nullptr || vcpu->current_vmcs_gpa == ~0ULL) return nullptr;
    return FindVmcs(vcpu, vcpu->current_vmcs_gpa);
}

const NestedVmcs12* CurrentVmcs(const NestedVcpu* vcpu) {
    return CurrentVmcs(const_cast<NestedVcpu*>(vcpu));
}

void SetVmcsReadOnly(NestedVmcs12* vmcs, u32 encoding, u64 value) {
    if (vmcs == nullptr) return;
    const FieldRule* rule = FindFieldRule(encoding);
    if (rule == nullptr || FieldIndex(rule) >= kNestedVmcsFields) return;
    vmcs->fields[FieldIndex(rule)] = value & FieldMask(rule->width);
}

bool ValidateControlValue(const NestedVcpu* vcpu, const FieldRule& rule,
                          u64 value) {
    if (vcpu == nullptr) return false;
    if ((value & rule.reserved_zero_mask) != 0 ||
        (value & rule.reserved_one_mask) != rule.reserved_one_mask) {
        return false;
    }
    const u32 requested = static_cast<u32>(value);
    u32 allowed0 = 0;
    u32 allowed1 = 0xFFFFFFFFU;
    switch (rule.control_kind) {
        case FieldControlPin:
            allowed0 = vcpu->capabilities.pin_allowed0;
            allowed1 = vcpu->capabilities.pin_allowed1;
            break;
        case FieldControlPrimary:
            allowed0 = vcpu->capabilities.primary_allowed0;
            allowed1 = vcpu->capabilities.primary_allowed1;
            break;
        case FieldControlSecondary:
            allowed0 = vcpu->capabilities.secondary_allowed0;
            allowed1 = vcpu->capabilities.secondary_allowed1;
            break;
        case FieldControlExit:
            allowed0 = vcpu->capabilities.exit_allowed0;
            allowed1 = vcpu->capabilities.exit_allowed1;
            break;
        case FieldControlEntry:
            allowed0 = vcpu->capabilities.entry_allowed0;
            allowed1 = vcpu->capabilities.entry_allowed1;
            break;
        default:
            return true;
    }
    const u32 adjusted = (requested | allowed0) & allowed1;
    return adjusted == requested;
}

bool ValidateEntryState(const NestedVcpu* vcpu, const NestedVmcs12& vmcs) {
    if (vcpu == nullptr) return false;
    const FieldRule* pin_rule = FindFieldRule(kVmcsFieldPinControls);
    const FieldRule* primary_rule = FindFieldRule(kVmcsFieldPrimaryControls);
    const FieldRule* secondary_rule =
        FindFieldRule(kVmcsFieldSecondaryControls);
    const FieldRule* exit_rule = FindFieldRule(kVmcsFieldExitControls);
    const FieldRule* entry_rule = FindFieldRule(kVmcsFieldEntryControls);
    const FieldRule* guest_cr0_rule = FindFieldRule(kVmcsFieldGuestCr0);
    const FieldRule* guest_cr4_rule = FindFieldRule(kVmcsFieldGuestCr4);
    const FieldRule* host_cr0_rule = FindFieldRule(kVmcsFieldHostCr0);
    const FieldRule* host_cr4_rule = FindFieldRule(kVmcsFieldHostCr4);
    const FieldRule* guest_rip_rule = FindFieldRule(kVmcsFieldGuestRip);
    const FieldRule* guest_rsp_rule = FindFieldRule(kVmcsFieldGuestRsp);
    const FieldRule* host_rip_rule = FindFieldRule(kVmcsFieldHostRip);
    const FieldRule* host_rsp_rule = FindFieldRule(kVmcsFieldHostRsp);
    const FieldRule* guest_rflags_rule = FindFieldRule(kVmcsFieldGuestRflags);
    const FieldRule* ept_pointer_rule = FindFieldRule(kVmcsFieldEptPointer);
    const FieldRule* vpid_rule = FindFieldRule(kVmcsFieldVpid);
    if (pin_rule == nullptr || primary_rule == nullptr ||
        secondary_rule == nullptr || exit_rule == nullptr ||
        entry_rule == nullptr || guest_cr0_rule == nullptr ||
        guest_cr4_rule == nullptr || host_cr0_rule == nullptr ||
        host_cr4_rule == nullptr || guest_rip_rule == nullptr ||
        guest_rsp_rule == nullptr || host_rip_rule == nullptr ||
        host_rsp_rule == nullptr || guest_rflags_rule == nullptr ||
        ept_pointer_rule == nullptr || vpid_rule == nullptr) {
        return false;
    }
    const u64 primary = ReadStoredField(vmcs, *primary_rule);
    const u64 secondary = ReadStoredField(vmcs, *secondary_rule);
    if (!ValidateControlValue(vcpu, *pin_rule,
                              ReadStoredField(vmcs, *pin_rule)) ||
        !ValidateControlValue(vcpu, *primary_rule, primary) ||
        !ValidateControlValue(vcpu, *secondary_rule, secondary) ||
        !ValidateControlValue(vcpu, *exit_rule,
                              ReadStoredField(vmcs, *exit_rule)) ||
        !ValidateControlValue(vcpu, *entry_rule,
                              ReadStoredField(vmcs, *entry_rule))) {
        return false;
    }
    if ((secondary != 0) && (primary & kPrimaryActivateSecondary) == 0) {
        return false;
    }
    const u64 guest_cr0 = ReadStoredField(vmcs, *guest_cr0_rule);
    const u64 guest_cr4 = ReadStoredField(vmcs, *guest_cr4_rule);
    const u64 host_cr0 = ReadStoredField(vmcs, *host_cr0_rule);
    const u64 host_cr4 = ReadStoredField(vmcs, *host_cr4_rule);
    if (!IsFixedCrValid(guest_cr0, vcpu->capabilities.cr0_fixed0,
                        vcpu->capabilities.cr0_fixed1) ||
        !IsFixedCrValid(host_cr0, vcpu->capabilities.cr0_fixed0,
                        vcpu->capabilities.cr0_fixed1) ||
        !IsFixedCrValid(guest_cr4, vcpu->capabilities.cr4_fixed0,
                        vcpu->capabilities.cr4_fixed1) ||
        !IsFixedCrValid(host_cr4, vcpu->capabilities.cr4_fixed0,
                        vcpu->capabilities.cr4_fixed1)) {
        return false;
    }
    const u64 guest_rip = ReadStoredField(vmcs, *guest_rip_rule);
    const u64 guest_rsp = ReadStoredField(vmcs, *guest_rsp_rule);
    const u64 host_rip = ReadStoredField(vmcs, *host_rip_rule);
    const u64 host_rsp = ReadStoredField(vmcs, *host_rsp_rule);
    if (!IsCanonicalAddress(guest_rip,
                            vcpu->capabilities.linear_address_bits) ||
        !IsCanonicalAddress(guest_rsp,
                            vcpu->capabilities.linear_address_bits) ||
        !IsCanonicalAddress(host_rip,
                            vcpu->capabilities.linear_address_bits) ||
        !IsCanonicalAddress(host_rsp,
                            vcpu->capabilities.linear_address_bits)) {
        return false;
    }
    const u64 rflags = ReadStoredField(vmcs, *guest_rflags_rule);
    if ((rflags & 2ULL) == 0) return false;
    if ((secondary & kNestedSecondaryEnableEpt) != 0) {
        if ((vcpu->capabilities.feature_bits & kCapEpt) == 0) return false;
        const u64 eptp = ReadStoredField(vmcs, *ept_pointer_rule);
        if (!IsAlignedPage(eptp) ||
            !IsPhysicalAddress(eptp,
                               vcpu->capabilities.max_physical_address_bits)) {
            return false;
        }
    }
    if ((secondary & kNestedSecondaryEnableVpid) != 0) {
        if ((vcpu->capabilities.feature_bits & kCapVpid) == 0) return false;
        const u64 vpid = ReadStoredField(vmcs, *vpid_rule);
        if (vpid == 0 || vpid > vcpu->capabilities.vpid_count) return false;
    }
    if ((secondary & kNestedSecondaryEnableVmfunc) != 0 &&
        (vcpu->capabilities.feature_bits & kCapVirtualTlbFlush) == 0) {
        return false;
    }
    return true;
}

// the VMX memory operand contains a physical GPA, not the region bytes
bool ValidateVmxRegion(NestedVcpu* vcpu, u64 operand_linear,
                       u64* region_gpa) {
    if (vcpu == nullptr || region_gpa == nullptr ||
        !IsLinearRangeCanonical(vcpu, operand_linear, sizeof(u64))) {
        return false;
    }
    u64 region = 0;
    if (!ReadLinear(vcpu->memory, operand_linear, &region, sizeof(region),
                    static_cast<u32>(NestedMemoryAccess::Read)) ||
        !IsAlignedPage(region) ||
        !IsPhysicalAddress(region,
                           vcpu->capabilities.max_physical_address_bits) ||
        region > ~0ULL - (kNestedPageSize - 1U) ||
        !IsPhysicalAddress(region + (kNestedPageSize - 1U),
                           vcpu->capabilities.max_physical_address_bits) ||
        vcpu->memory.read == nullptr) {
        return false;
    }
    u32 revision = 0;
    if (!vcpu->memory.read(vcpu->memory.context, region, &revision,
                           sizeof(revision))) {
        return false;
    }
    // validate every byte so a sparse or partially mapped page cannot be
    // mistaken for a usable VMX region
    u8 scratch[64] = {};
    u32 offset = sizeof(revision);
    while (offset < kNestedPageSize) {
        const u32 remaining = kNestedPageSize - offset;
        const u32 chunk = remaining < sizeof(scratch)
                              ? remaining
                              : static_cast<u32>(sizeof(scratch));
        if (!vcpu->memory.read(vcpu->memory.context, region + offset, scratch,
                               chunk)) {
            return false;
        }
        offset += chunk;
    }
    if ((revision & ~kNestedVmxRevisionMask) != 0 ||
        (revision & kNestedVmxRevisionMask) !=
        (vcpu->capabilities.vmx_revision & kNestedVmxRevisionMask)) {
        return false;
    }
    *region_gpa = region;
    return true;
}

bool ReadNestedVmcsField(const NestedVcpu* vcpu, u32 encoding, u64* value) {
    if (value == nullptr) return false;
    const NestedVmcs12* vmcs = CurrentVmcs(vcpu);
    const FieldRule* rule = FindFieldRule(encoding);
    if (vmcs == nullptr || rule == nullptr || FieldIndex(rule) >= kNestedVmcsFields) {
        return false;
    }
    *value = vmcs->fields[FieldIndex(rule)] & FieldMask(rule->width);
    return true;
}

bool WriteNestedVmcsField(NestedVcpu* vcpu, u32 encoding, u64 value) {
    if (vcpu == nullptr) return false;
    NestedVmcs12* vmcs = CurrentVmcs(vcpu);
    const FieldRule* rule = FindFieldRule(encoding);
    if (vmcs == nullptr || rule == nullptr || rule->writable == 0 ||
        FieldIndex(rule) >= kNestedVmcsFields ||
        (value & rule->reserved_zero_mask) != 0 ||
        (value & rule->reserved_one_mask) != rule->reserved_one_mask ||
        !ValidateControlValue(vcpu, *rule, value)) {
        return false;
    }
    WriteStoredField(*vmcs, *rule, value);
    return true;
}

void InitializeCapabilitiesInternal(NestedCapabilities* capabilities) {
    if (capabilities == nullptr) return;
    *capabilities = {};
    capabilities->version = kNestedModelVersion;
    capabilities->size = sizeof(NestedCapabilities);
    capabilities->feature_bits = kCapVmx | kCapEpt | kCapVpid |
                                 kCapNestedVmx | kCapVirtualTlbFlush;
    capabilities->vmx_revision = 1U;
    capabilities->max_physical_address_bits = 48U;
    capabilities->linear_address_bits = 48U;
    capabilities->eptp_list_entries = 4U;
    capabilities->vpid_count = 64U;
    capabilities->pin_allowed1 = 0x000000E9U;
    capabilities->primary_allowed1 = kPrimaryActivateSecondary | 0x40000000U;
    capabilities->secondary_allowed1 = kNestedSecondaryEnableEpt |
                                       kNestedSecondaryEnableVpid |
                                       kNestedSecondaryEnableVmfunc;
    capabilities->exit_allowed1 = 0x003F6DFFU;
    capabilities->entry_allowed1 = 0x001811FFU;
    capabilities->cr0_fixed1 = ~0ULL;
    capabilities->cr4_fixed1 = ~0ULL;
}

void InitializeNestedVcpu(NestedVcpu* vcpu,
                          const NestedCapabilities* capabilities,
                          const NestedMemory* memory) {
    if (vcpu == nullptr) return;
    *vcpu = {};
    vcpu->version = kNestedModelVersion;
    vcpu->size = sizeof(NestedVcpu);
    if (capabilities != nullptr &&
        IsVersionedBufferValid(capabilities->version, capabilities->size,
                               sizeof(NestedCapabilities))) {
        vcpu->capabilities = *capabilities;
    } else {
        InitializeCapabilitiesInternal(&vcpu->capabilities);
    }
    if (memory != nullptr) vcpu->memory = *memory;
    vcpu->current_vmcs_gpa = ~0ULL;
    vcpu->generation = 1U;
    for (u32 index = 0; index < kNestedVmcsSlots; ++index) {
        vcpu->vmcs[index].region_gpa = 0;
        vcpu->vmcs[index].revision =
            vcpu->capabilities.vmx_revision & kNestedVmxRevisionMask;
        vcpu->vmcs[index].state = Vmcs12State::Clear;
        vcpu->vmcs[index].allocated = 0;
        vcpu->vmcs[index].dirty_groups = 0;
    }
}

}  // namespace nested_internal

void InitializeNestedCapabilities(NestedCapabilities* capabilities) {
    nested_internal::InitializeCapabilitiesInternal(capabilities);
}

void InitializeNestedVcpu(NestedVcpu* vcpu,
                          const NestedCapabilities* capabilities,
                          const NestedMemory* memory) {
    nested_internal::InitializeNestedVcpu(vcpu, capabilities, memory);
}

bool ReadNestedVmcsField(const NestedVcpu* vcpu, u32 encoding, u64* value) {
    return nested_internal::ReadNestedVmcsField(vcpu, encoding, value);
}

bool WriteNestedVmcsField(NestedVcpu* vcpu, u32 encoding, u64 value) {
    return nested_internal::WriteNestedVmcsField(vcpu, encoding, value);
}

}  // namespace knhv
