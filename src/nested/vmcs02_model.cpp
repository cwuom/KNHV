#include "knhv_vmcs02.h"

namespace knhv {
namespace {

constexpr u32 kKnownVmcs12StateMask =
    static_cast<u32>(Vmcs12State::Clear) |
    static_cast<u32>(Vmcs12State::Active) |
    static_cast<u32>(Vmcs12State::Launched);

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kVmcs02ModelVersion && size >= required &&
           size <= kVmcs02MaxStructSize;
}

bool IsCanonical(u64 value, u32 address_bits) {
    const u32 bits = address_bits >= 48U && address_bits <= 63U
                         ? address_bits
                         : 48U;
    const u64 low_mask = (1ULL << bits) - 1ULL;
    const u64 upper = value & ~low_mask;
    return (value & (1ULL << (bits - 1U))) == 0 ? upper == 0
                                                : upper == ~low_mask;
}

bool IsPhysical(u64 value, u32 address_bits) {
    return address_bits >= 1U && address_bits <= 52U &&
           (value >> address_bits) == 0;
}

bool IsFixedCrValid(u64 value, u64 fixed0, u64 fixed1) {
    return (value & fixed0) == fixed0 &&
           (fixed1 == 0 || (value & ~fixed1) == 0);
}

bool AdjustControl(u32 requested, u32 required, u32 forbidden, u32 allowed0,
                   u32 allowed1, u32* adjusted) {
    if (adjusted == nullptr || (requested & ~allowed1) != 0 ||
        (required & ~allowed1) != 0 || (required & forbidden) != 0) {
        return false;
    }
    const u32 value = (requested | required | allowed0) & allowed1;
    if ((value & forbidden) != 0) return false;
    *adjusted = value;
    return true;
}

bool ReadField(const NestedVcpu* vcpu, const NestedVmcs12* vmcs, u32 encoding,
               u64* value) {
    return vcpu != nullptr && vmcs != nullptr && value != nullptr &&
           vcpu->current_vmcs_gpa == vmcs->region_gpa &&
           ReadNestedVmcsField(vcpu, encoding, value);
}

bool IsVmcsPointerOwned(const NestedVcpu* vcpu, const NestedVmcs12* vmcs) {
    if (vcpu == nullptr || vmcs == nullptr) return false;
    for (u32 index = 0; index < kNestedVmcsSlots; ++index) {
        if (&vcpu->vmcs[index] == vmcs) return true;
    }
    return false;
}

bool IsVmcs12StateValue(u32 state) {
    return (state & ~kKnownVmcs12StateMask) == 0 &&
           (state == static_cast<u32>(Vmcs12State::Clear) ||
            state == static_cast<u32>(Vmcs12State::Active) ||
            state == static_cast<u32>(Vmcs12State::Launched));
}

bool IsAlignedPhysical(u64 value, u32 bits) {
    return (value & (kNestedPageSize - 1ULL)) == 0 &&
           IsPhysical(value, bits);
}

bool IsAddressSetValid(u64 value, u32 bits) {
    return value == 0 || IsAlignedPhysical(value, bits);
}

bool IsCapabilitiesContractValid(const NestedCapabilities* capabilities) {
    return capabilities != nullptr &&
           IsVersionedSizeValid(capabilities->version, capabilities->size,
                                sizeof(NestedCapabilities)) &&
           capabilities->max_physical_address_bits >= 1U &&
           capabilities->max_physical_address_bits <= 52U &&
           capabilities->linear_address_bits >= 48U &&
           capabilities->linear_address_bits <= 63U;
}

bool IsPolicyContractValid(const Vmcs02Policy* policy) {
    if (policy == nullptr ||
        !IsVersionedSizeValid(policy->version, policy->size,
                              sizeof(Vmcs02Policy)) ||
        policy->reserved != 0 || policy->generation == 0) {
        return false;
    }
    return (policy->required_pin_controls & policy->forbidden_pin_controls) ==
               0 &&
           (policy->required_primary_controls &
            policy->forbidden_primary_controls) == 0 &&
           (policy->required_secondary_controls &
            policy->forbidden_secondary_controls) == 0 &&
           (policy->required_exit_controls & policy->forbidden_exit_controls) ==
               0 &&
           (policy->required_entry_controls &
            policy->forbidden_entry_controls) == 0;
}

bool ControlMatches(u32 value, u32 required, u32 forbidden, u32 allowed0,
                    u32 allowed1) {
    u32 adjusted = 0;
    return AdjustControl(value, required, forbidden, allowed0, allowed1,
                         &adjusted) &&
           adjusted == value;
}

bool ValidateEptPointer(u64 raw, u32 bits) {
    EptpConfig config = {};
    if (!DecodeEptPointer(raw, &config)) return false;
    config.generation = 1;
    return IsEptpConfigValid(&config, bits);
}

}  // namespace

bool ReadVmcs12Model(const NestedVcpu* vcpu, const NestedVmcs12* vmcs,
                     Vmcs12Model* model) {
    if (model == nullptr || vcpu == nullptr || vmcs == nullptr ||
        vcpu->version != kNestedModelVersion ||
        vcpu->size < sizeof(NestedVcpu) || vmcs->allocated == 0 ||
        !IsVmcsPointerOwned(vcpu, vmcs) ||
        vmcs->revision !=
            (vcpu->capabilities.vmx_revision & kNestedVmxRevisionMask) ||
        vcpu->current_vmcs_gpa != vmcs->region_gpa) {
        return false;
    }
    *model = {};
    model->size = sizeof(*model);
    model->version = kVmcs02ModelVersion;
    model->revision = vmcs->revision;
    model->state = static_cast<u32>(vmcs->state);
    u64 value = 0;
    if (!ReadField(vcpu, vmcs, kVmcsFieldPinControls, &value)) return false;
    model->pin_controls = static_cast<u32>(value);
    if (!ReadField(vcpu, vmcs, kVmcsFieldPrimaryControls, &value)) return false;
    model->primary_controls = static_cast<u32>(value);
    if (!ReadField(vcpu, vmcs, kVmcsFieldSecondaryControls, &value)) return false;
    model->secondary_controls = static_cast<u32>(value);
    if (!ReadField(vcpu, vmcs, kVmcsFieldExitControls, &value)) return false;
    model->exit_controls = static_cast<u32>(value);
    if (!ReadField(vcpu, vmcs, kVmcsFieldEntryControls, &value)) return false;
    model->entry_controls = static_cast<u32>(value);
    if (!ReadField(vcpu, vmcs, kVmcsFieldExceptionBitmap, &value)) return false;
    model->exception_bitmap = static_cast<u32>(value);
    if (!ReadField(vcpu, vmcs, kVmcsFieldGuestCr0, &model->guest_cr0) ||
        !ReadField(vcpu, vmcs, kVmcsFieldGuestCr3, &model->guest_cr3) ||
        !ReadField(vcpu, vmcs, kVmcsFieldGuestCr4, &model->guest_cr4) ||
        !ReadField(vcpu, vmcs, kVmcsFieldGuestRip, &model->guest_rip) ||
        !ReadField(vcpu, vmcs, kVmcsFieldGuestRsp, &model->guest_rsp) ||
        !ReadField(vcpu, vmcs, kVmcsFieldGuestRflags, &model->guest_rflags) ||
        !ReadField(vcpu, vmcs, kVmcsFieldEptPointer, &model->ept_pointer) ||
        !ReadField(vcpu, vmcs, kVmcsFieldVpid, &model->vpid)) {
        return false;
    }
    return true;
}

bool IsVmcs12ModelValid(const Vmcs12Model* model,
                        const NestedCapabilities* capabilities) {
    if (model == nullptr || capabilities == nullptr ||
        !IsVersionedSizeValid(model->version, model->size,
                              sizeof(Vmcs12Model)) ||
        !IsCapabilitiesContractValid(capabilities) ||
        !IsVmcs12StateValue(model->state) ||
        model->state == static_cast<u32>(Vmcs12State::Clear) ||
        model->revision !=
            (capabilities->vmx_revision & kNestedVmxRevisionMask) ||
        model->reserved != 0 ||
        !IsFixedCrValid(model->guest_cr0, capabilities->cr0_fixed0,
                        capabilities->cr0_fixed1) ||
        !IsFixedCrValid(model->guest_cr4, capabilities->cr4_fixed0,
                        capabilities->cr4_fixed1) ||
        !IsCanonical(model->guest_rip, capabilities->linear_address_bits) ||
        !IsCanonical(model->guest_rsp, capabilities->linear_address_bits) ||
        (model->guest_rflags & 2ULL) == 0 ||
        !IsPhysical(model->guest_cr3,
                    capabilities->max_physical_address_bits)) {
        return false;
    }
    if ((model->secondary_controls & kNestedSecondaryEnableEpt) != 0 &&
        ((capabilities->feature_bits & kCapEpt) == 0 ||
         !ValidateEptPointer(model->ept_pointer,
                              capabilities->max_physical_address_bits))) {
        return false;
    }
    if ((model->secondary_controls & kNestedSecondaryEnableVpid) != 0 &&
        ((capabilities->feature_bits & kCapVpid) == 0 || model->vpid == 0 ||
         model->vpid > capabilities->vpid_count)) {
        return false;
    }
    if ((model->secondary_controls & kNestedSecondaryEnableVmfunc) != 0 &&
        (capabilities->feature_bits & kCapVirtualTlbFlush) == 0) {
        return false;
    }
    return true;
}

Vmcs02BuildStatus BuildVmcs02Model(const Vmcs12Model* vmcs12,
                                    const NestedCapabilities* capabilities,
                                    const Vmcs02Policy* policy,
                                    Vmcs02Image* image) {
    if (image == nullptr) return Vmcs02BuildStatus::InvalidParameter;
    *image = {};
    image->size = sizeof(*image);
    image->version = kVmcs02ModelVersion;
    if (vmcs12 == nullptr || capabilities == nullptr || policy == nullptr) {
        image->status = static_cast<u32>(
            Vmcs02BuildStatus::InvalidParameter);
        return static_cast<Vmcs02BuildStatus>(image->status);
    }
    if (!IsCapabilitiesContractValid(capabilities) ||
        !IsPolicyContractValid(policy)) {
        image->status = static_cast<u32>(Vmcs02BuildStatus::InvalidParameter);
        return Vmcs02BuildStatus::InvalidParameter;
    }
    if (!IsVmcs12ModelValid(vmcs12, capabilities)) {
        image->status = static_cast<u32>(Vmcs02BuildStatus::Vmcs12Invalid);
        return Vmcs02BuildStatus::Vmcs12Invalid;
    }
    if (!AdjustControl(vmcs12->pin_controls, policy->required_pin_controls,
                       policy->forbidden_pin_controls,
                       capabilities->pin_allowed0, capabilities->pin_allowed1,
                       &image->pin_controls) ||
        !AdjustControl(vmcs12->primary_controls,
                       policy->required_primary_controls,
                       policy->forbidden_primary_controls,
                       capabilities->primary_allowed0,
                       capabilities->primary_allowed1,
                       &image->primary_controls) ||
        !AdjustControl(vmcs12->secondary_controls,
                       policy->required_secondary_controls,
                       policy->forbidden_secondary_controls,
                       capabilities->secondary_allowed0,
                       capabilities->secondary_allowed1,
                       &image->secondary_controls) ||
        !AdjustControl(vmcs12->exit_controls, policy->required_exit_controls,
                       policy->forbidden_exit_controls,
                       capabilities->exit_allowed0, capabilities->exit_allowed1,
                       &image->exit_controls) ||
        !AdjustControl(vmcs12->entry_controls,
                       policy->required_entry_controls,
                       policy->forbidden_entry_controls,
                       capabilities->entry_allowed0,
                       capabilities->entry_allowed1,
                       &image->entry_controls)) {
        image->status = static_cast<u32>(Vmcs02BuildStatus::ControlConflict);
        return Vmcs02BuildStatus::ControlConflict;
    }
    if (image->secondary_controls != 0 &&
        (image->primary_controls & kVmcs02PrimaryActivateSecondary) == 0) {
        if ((capabilities->primary_allowed1 &
             kVmcs02PrimaryActivateSecondary) == 0 ||
            (policy->forbidden_primary_controls &
             kVmcs02PrimaryActivateSecondary) != 0) {
            image->status = static_cast<u32>(
                Vmcs02BuildStatus::CapabilityMismatch);
            return Vmcs02BuildStatus::CapabilityMismatch;
        }
        image->primary_controls |= kVmcs02PrimaryActivateSecondary;
    }
    const bool ept_enabled =
        (image->secondary_controls & kNestedSecondaryEnableEpt) != 0;
    if (ept_enabled) {
        const u64 raw_eptp = policy->ept_pointer == 0 ? vmcs12->ept_pointer
                                                       : policy->ept_pointer;
        if (!ValidateEptPointer(raw_eptp,
                                capabilities->max_physical_address_bits)) {
            image->status = static_cast<u32>(Vmcs02BuildStatus::AddressInvalid);
            return Vmcs02BuildStatus::AddressInvalid;
        }
        image->ept_pointer = raw_eptp;
    } else if (policy->ept_pointer != 0) {
        image->status = static_cast<u32>(Vmcs02BuildStatus::ControlConflict);
        return Vmcs02BuildStatus::ControlConflict;
    }
    if (!IsPhysical(policy->host_cr3,
                    capabilities->max_physical_address_bits) ||
        !IsCanonical(policy->host_rip, capabilities->linear_address_bits) ||
        !IsCanonical(policy->host_rsp, capabilities->linear_address_bits) ||
        !IsFixedCrValid(policy->host_cr0, capabilities->cr0_fixed0,
                        capabilities->cr0_fixed1) ||
        !IsFixedCrValid(policy->host_cr4, capabilities->cr4_fixed0,
                        capabilities->cr4_fixed1) ||
        !IsAddressSetValid(policy->io_bitmap_a,
                           capabilities->max_physical_address_bits) ||
        !IsAddressSetValid(policy->io_bitmap_b,
                           capabilities->max_physical_address_bits) ||
        !IsAddressSetValid(policy->msr_bitmap,
                           capabilities->max_physical_address_bits)) {
        image->status = static_cast<u32>(Vmcs02BuildStatus::AddressInvalid);
        return Vmcs02BuildStatus::AddressInvalid;
    }
    image->exception_bitmap = vmcs12->exception_bitmap;
    image->guest_cr0 = vmcs12->guest_cr0;
    image->guest_cr3 = vmcs12->guest_cr3;
    image->guest_cr4 = vmcs12->guest_cr4;
    image->guest_rip = vmcs12->guest_rip;
    image->guest_rsp = vmcs12->guest_rsp;
    image->guest_rflags = vmcs12->guest_rflags;
    image->host_cr0 = policy->host_cr0;
    image->host_cr3 = policy->host_cr3;
    image->host_cr4 = policy->host_cr4;
    image->host_rsp = policy->host_rsp;
    image->host_rip = policy->host_rip;
    image->io_bitmap_a = policy->io_bitmap_a;
    image->io_bitmap_b = policy->io_bitmap_b;
    image->msr_bitmap = policy->msr_bitmap;
    image->generation = policy->generation;
    image->status = static_cast<u32>(Vmcs02BuildStatus::Success);
    return Vmcs02BuildStatus::Success;
}

bool IsVmcs02ImageValid(const Vmcs02Image* image,
                        const NestedCapabilities* capabilities,
                        const Vmcs02Policy* policy) {
    if (image == nullptr || capabilities == nullptr || policy == nullptr ||
        !IsCapabilitiesContractValid(capabilities) ||
        !IsPolicyContractValid(policy) ||
        !IsVersionedSizeValid(image->version, image->size,
                              sizeof(Vmcs02Image)) ||
        image->status != static_cast<u32>(Vmcs02BuildStatus::Success) ||
        image->reserved != 0 || image->reserved2 != 0 ||
        image->generation != policy->generation ||
        !IsFixedCrValid(image->guest_cr0, capabilities->cr0_fixed0,
                        capabilities->cr0_fixed1) ||
        !IsFixedCrValid(image->guest_cr4, capabilities->cr4_fixed0,
                        capabilities->cr4_fixed1) ||
        !IsFixedCrValid(image->host_cr0, capabilities->cr0_fixed0,
                        capabilities->cr0_fixed1) ||
        !IsFixedCrValid(image->host_cr4, capabilities->cr4_fixed0,
                        capabilities->cr4_fixed1) ||
        !IsCanonical(image->guest_rip, capabilities->linear_address_bits) ||
        !IsCanonical(image->guest_rsp, capabilities->linear_address_bits) ||
        !IsCanonical(image->host_rip, capabilities->linear_address_bits) ||
        !IsCanonical(image->host_rsp, capabilities->linear_address_bits) ||
        !IsPhysical(image->guest_cr3,
                    capabilities->max_physical_address_bits) ||
        !IsPhysical(image->host_cr3,
                    capabilities->max_physical_address_bits) ||
        !ControlMatches(image->pin_controls,
                        policy->required_pin_controls,
                        policy->forbidden_pin_controls,
                        capabilities->pin_allowed0,
                        capabilities->pin_allowed1) ||
        !ControlMatches(image->primary_controls,
                        policy->required_primary_controls,
                        policy->forbidden_primary_controls,
                        capabilities->primary_allowed0,
                        capabilities->primary_allowed1) ||
        !ControlMatches(image->secondary_controls,
                        policy->required_secondary_controls,
                        policy->forbidden_secondary_controls,
                        capabilities->secondary_allowed0,
                        capabilities->secondary_allowed1) ||
        !ControlMatches(image->exit_controls,
                        policy->required_exit_controls,
                        policy->forbidden_exit_controls,
                        capabilities->exit_allowed0,
                        capabilities->exit_allowed1) ||
        !ControlMatches(image->entry_controls,
                        policy->required_entry_controls,
                        policy->forbidden_entry_controls,
                        capabilities->entry_allowed0,
                        capabilities->entry_allowed1) ||
        (image->secondary_controls != 0 &&
         (image->primary_controls & kVmcs02PrimaryActivateSecondary) == 0)) {
        return false;
    }
    if ((image->secondary_controls & kNestedSecondaryEnableEpt) != 0 &&
        !ValidateEptPointer(image->ept_pointer,
                            capabilities->max_physical_address_bits)) {
        return false;
    }
    return true;
}

}  // namespace knhv
