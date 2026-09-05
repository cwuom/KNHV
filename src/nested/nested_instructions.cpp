#include "nested_internal.h"

namespace knhv {
namespace {

constexpr u32 kErrorVmxonInVmxOperation = 15U;
constexpr u32 kErrorVmclearInvalidAddress = 2U;
constexpr u32 kErrorVmclearVmxonPointer = 3U;
constexpr u32 kErrorVmptrldInvalidAddress = 9U;
constexpr u32 kErrorVmptrldVmxonPointer = 10U;
constexpr u32 kErrorVmreadNoCurrent = 12U;
constexpr u32 kErrorVmwriteNoCurrent = 13U;
constexpr u32 kErrorVmlaunchNonclear = 4U;
constexpr u32 kErrorVmresumeNonlaunched = 5U;
constexpr u32 kErrorVmEntryInvalidControl = 7U;
constexpr u32 kErrorInvalidOperand = 1U;

struct InveptDescriptor {
    u64 ept_pointer;
    u64 reserved;
};

struct InvvpidDescriptor {
    u64 vpid;
    u64 linear_address;
};

u32 InstructionLength(const VmxInstruction& instruction) {
    return instruction.instruction_length == 0
               ? 3U
               : instruction.instruction_length;
}

bool InstructionIsValid(const VmxInstruction& instruction) {
    return instruction.version == kNestedModelVersion &&
           instruction.size >= sizeof(VmxInstruction) &&
           instruction.size <= sizeof(VmxInstruction) + 64U &&
           instruction.reserved == 0 && instruction.reserved2 == 0 &&
           (instruction.flags &
            ~(kInstructionOperandIsRegister | kDescriptorIsInline)) == 0 &&
           InstructionLength(instruction) <= 15U;
}

NestedResult InvalidInstruction(const VmxInstruction& instruction) {
    return nested_internal::MakeResult(
        HvStatus::InvalidParameter, NestedAction::ResumeL1, 0U,
        InstructionLength(instruction), 0, 0);
}

NestedResult UndefinedInstruction(const VmxInstruction& instruction) {
    return nested_internal::MakeResult(
        HvStatus::VirtualUnsupported,
        NestedAction::InjectUndefinedInstruction, 0U,
        InstructionLength(instruction), 0, 0);
}

bool ReadDescriptor(const NestedVcpu& vcpu, const VmxInstruction& instruction,
                    void* descriptor, u32 length) {
    if ((instruction.flags & kDescriptorIsInline) != 0) {
        if (length != sizeof(InveptDescriptor) &&
            length != sizeof(InvvpidDescriptor)) {
            return false;
        }
        const u64 words[2] = {instruction.descriptor,
                              instruction.destination};
        u8* destination = static_cast<u8*>(descriptor);
        for (u32 index = 0; index < length; ++index) {
            destination[index] = reinterpret_cast<const u8*>(words)[index];
        }
        return true;
    }
    return nested_internal::IsLinearRangeCanonical(
               &vcpu, instruction.linear_operand, length) &&
           nested_internal::ReadLinear(
               vcpu.memory, instruction.linear_operand, descriptor, length,
               static_cast<u32>(NestedMemoryAccess::Read));
}

NestedResult EmulateVmxon(NestedVcpu* vcpu,
                          const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if (vcpu->vmxon_active != 0) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmxonInVmxOperation, length);
    }
    if ((vcpu->capabilities.feature_bits & kCapNestedVmx) == 0 ||
        vcpu->vmxe_enabled == 0) {
        return nested_internal::MakeResult(
            HvStatus::NestedUnavailable, NestedAction::ResumeL1, 0U, length,
            0, 0);
    }
    u64 region_gpa = 0;
    if (!nested_internal::ValidateVmxRegion(vcpu, instruction.linear_operand,
                                            &region_gpa)) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }
    vcpu->vmxon_active = 1;
    vcpu->vmxon_gpa = region_gpa;
    vcpu->current_vmcs_gpa = ~0ULL;
    vcpu->l2_running = 0;
    ++vcpu->generation;
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmxoff(NestedVcpu* vcpu,
                           const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if (vcpu->vmxon_active == 0) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }
    if (vcpu->l2_running != 0) {
        return nested_internal::MakeResult(HvStatus::Busy,
                                           NestedAction::ResumeL1, 0U, length,
                                           0, 0);
    }
    vcpu->vmxon_active = 0;
    vcpu->l2_running = 0;
    vcpu->current_vmcs_gpa = ~0ULL;
    ++vcpu->generation;
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedVmcs12* AllocateVmcs(NestedVcpu* vcpu, u64 region_gpa) {
    NestedVmcs12* free_vmcs = nullptr;
    for (u32 index = 0; index < kNestedVmcsSlots; ++index) {
        NestedVmcs12* vmcs = &vcpu->vmcs[index];
        if (vmcs->allocated != 0 && vmcs->region_gpa == region_gpa) {
            return vmcs;
        }
        if (free_vmcs == nullptr && vmcs->allocated == 0) free_vmcs = vmcs;
    }
    if (free_vmcs == nullptr) return nullptr;
    *free_vmcs = {};
    free_vmcs->allocated = 1;
    free_vmcs->region_gpa = region_gpa;
    free_vmcs->revision =
        vcpu->capabilities.vmx_revision & kNestedVmxRevisionMask;
    free_vmcs->state = Vmcs12State::Clear;
    ++vcpu->vmcs_count;
    return free_vmcs;
}

NestedResult EmulateVmclear(NestedVcpu* vcpu,
                            const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if (vcpu->l2_running != 0) {
        return nested_internal::MakeResult(HvStatus::Busy,
                                           NestedAction::ResumeL1, 0U, length,
                                           0, 0);
    }
    u64 region_gpa = 0;
    if (!nested_internal::ValidateVmxRegion(vcpu, instruction.linear_operand,
                                            &region_gpa)) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorVmclearInvalidAddress,
            length);
    }
    if (region_gpa == vcpu->vmxon_gpa) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmclearVmxonPointer, length);
    }
    NestedVmcs12* vmcs = AllocateVmcs(vcpu, region_gpa);
    if (vmcs == nullptr) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::CapabilityMismatch, kErrorInvalidOperand, length);
    }
    const u32 revision = vmcs->revision;
    const u64 address = vmcs->region_gpa;
    *vmcs = {};
    vmcs->allocated = 1;
    vmcs->region_gpa = address;
    vmcs->revision = revision;
    vmcs->state = Vmcs12State::Clear;
    if (vcpu->current_vmcs_gpa == region_gpa) vcpu->current_vmcs_gpa = ~0ULL;
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmptrld(NestedVcpu* vcpu,
                            const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    u64 region_gpa = 0;
    if (!nested_internal::ValidateVmxRegion(vcpu, instruction.linear_operand,
                                            &region_gpa)) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorVmptrldInvalidAddress,
            length);
    }
    if (region_gpa == vcpu->vmxon_gpa) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmptrldVmxonPointer, length);
    }
    NestedVmcs12* vmcs = AllocateVmcs(vcpu, region_gpa);
    if (vmcs == nullptr) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::CapabilityMismatch, kErrorInvalidOperand, length);
    }
    if (vmcs->state == Vmcs12State::Active &&
        vcpu->current_vmcs_gpa != region_gpa) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorInvalidOperand, length);
    }
    vmcs->state = Vmcs12State::Active;
    vcpu->current_vmcs_gpa = region_gpa;
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmptrst(NestedVcpu* vcpu,
                            const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    const u64 current = vcpu->current_vmcs_gpa;
    if ((instruction.flags & kInstructionOperandIsRegister) != 0) {
        return nested_internal::MakeSuccess(NestedAction::ResumeL1, length,
                                            current);
    }
    if (!nested_internal::IsLinearRangeCanonical(
            vcpu, instruction.destination, sizeof(current)) ||
        !nested_internal::WriteLinear(vcpu->memory, instruction.destination,
                                      &current, sizeof(current))) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmread(NestedVcpu* vcpu,
                           const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if (nested_internal::CurrentVmcs(vcpu) == nullptr) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorVmreadNoCurrent, length);
    }
    u64 value = 0;
    if (!ReadNestedVmcsField(vcpu, instruction.encoding, &value)) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorVmreadNoCurrent, length);
    }
    if ((instruction.flags & kInstructionOperandIsRegister) != 0) {
        nested_internal::ClearVmInstructionError(vcpu);
        return nested_internal::MakeSuccess(NestedAction::ResumeL1, length,
                                            value);
    }
    if (!nested_internal::IsLinearRangeCanonical(
            vcpu, instruction.destination, sizeof(value)) ||
        !nested_internal::WriteLinear(vcpu->memory, instruction.destination,
                                      &value, sizeof(value))) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmwrite(NestedVcpu* vcpu,
                            const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if (nested_internal::CurrentVmcs(vcpu) == nullptr) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorVmwriteNoCurrent, length);
    }
    const nested_internal::FieldRule* rule =
        nested_internal::FindFieldRule(instruction.encoding);
    if (rule == nullptr || rule->writable == 0) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorVmwriteNoCurrent, length);
    }
    if (!WriteNestedVmcsField(vcpu, instruction.encoding, instruction.source)) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmEntryInvalidControl, length);
    }
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmEntry(NestedVcpu* vcpu,
                            const VmxInstruction& instruction,
                            bool launch) {
    const u32 length = InstructionLength(instruction);
    NestedVmcs12* vmcs = nested_internal::CurrentVmcs(vcpu);
    if (vmcs == nullptr) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid,
            launch ? kErrorVmlaunchNonclear : kErrorVmresumeNonlaunched,
            length);
    }
    if (launch && vmcs->state != Vmcs12State::Active) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmlaunchNonclear, length);
    }
    if (!launch && vmcs->state != Vmcs12State::Launched) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmresumeNonlaunched, length);
    }
    if (vcpu->l2_running != 0 ||
        !nested_internal::ValidateEntryState(vcpu, *vmcs)) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorVmEntryInvalidControl, length);
    }
    vmcs->state = Vmcs12State::Launched;
    vcpu->l2_running = 1;
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::EnterL2, length);
}

NestedResult EmulateInvept(NestedVcpu* vcpu,
                           const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if ((vcpu->capabilities.feature_bits & kCapEpt) == 0) {
        return nested_internal::MakeResult(
            HvStatus::VirtualUnsupported, NestedAction::VirtualUnsupported,
            0U, length, 0, 0);
    }
    InveptDescriptor descriptor = {};
    if (!ReadDescriptor(*vcpu, instruction, &descriptor, sizeof(descriptor)) ||
        descriptor.reserved != 0 ||
        (instruction.descriptor_type != 1U &&
         instruction.descriptor_type != 2U) ||
        (instruction.descriptor_type == 1U &&
         (!nested_internal::IsAlignedPage(descriptor.ept_pointer) ||
          !nested_internal::IsPhysicalAddress(
              descriptor.ept_pointer,
              vcpu->capabilities.max_physical_address_bits)))) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateInvvpid(NestedVcpu* vcpu,
                            const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    if ((vcpu->capabilities.feature_bits & kCapVpid) == 0) {
        return nested_internal::MakeResult(
            HvStatus::VirtualUnsupported, NestedAction::VirtualUnsupported,
            0U, length, 0, 0);
    }
    InvvpidDescriptor descriptor = {};
    if (!ReadDescriptor(*vcpu, instruction, &descriptor,
                        sizeof(descriptor)) ||
        descriptor.vpid == 0 || descriptor.vpid > vcpu->capabilities.vpid_count ||
        instruction.descriptor_type > 3U ||
        ((instruction.descriptor_type == 0U ||
         instruction.descriptor_type == 2U) &&
         !nested_internal::IsCanonicalAddress(
             descriptor.linear_address,
             vcpu->capabilities.linear_address_bits))) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

NestedResult EmulateVmfunc(NestedVcpu* vcpu,
                           const VmxInstruction& instruction) {
    const u32 length = InstructionLength(instruction);
    const NestedVmcs12* vmcs = nested_internal::CurrentVmcs(vcpu);
    u64 secondary = 0;
    if (vmcs == nullptr ||
        !ReadNestedVmcsField(vcpu, kVmcsFieldSecondaryControls, &secondary) ||
        (secondary & kNestedSecondaryEnableVmfunc) == 0) {
        return nested_internal::MakeResult(
            HvStatus::VirtualUnsupported, NestedAction::VirtualUnsupported,
            0U, length, 0, 0);
    }
    if (instruction.source != 0 ||
        instruction.descriptor_type >= vcpu->capabilities.eptp_list_entries) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailValid, kErrorInvalidOperand, length);
    }
    vcpu->eptp_index = instruction.descriptor_type;
    nested_internal::ClearVmInstructionError(vcpu);
    return nested_internal::MakeSuccess(NestedAction::ResumeL1, length);
}

}  // namespace

NestedResult DispatchNestedInstruction(NestedVcpu* vcpu,
                                       const VmxInstruction* instruction) {
    if (vcpu == nullptr || instruction == nullptr ||
        !InstructionIsValid(*instruction)) {
        if (instruction == nullptr) {
            return nested_internal::MakeResult(
                HvStatus::InvalidParameter, NestedAction::ResumeL1, 0U, 0U,
                0, 0);
        }
        return InvalidInstruction(*instruction);
    }
    const u32 length = InstructionLength(*instruction);
    if (instruction->opcode == VmxOpcode::Vmxon) {
        return EmulateVmxon(vcpu, *instruction);
    }
    if (instruction->opcode == VmxOpcode::Vmxoff) {
        if (vcpu->vmxon_active == 0) {
            return nested_internal::MakeVmfail(
                vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
        }
        return EmulateVmxoff(vcpu, *instruction);
    }
    if (vcpu->vmxon_active == 0) {
        return nested_internal::MakeVmfail(
            vcpu, HvStatus::VmfailInvalid, kErrorInvalidOperand, length);
    }

    switch (instruction->opcode) {
        case VmxOpcode::Vmclear:
            return EmulateVmclear(vcpu, *instruction);
        case VmxOpcode::Vmptrld:
            return EmulateVmptrld(vcpu, *instruction);
        case VmxOpcode::Vmptrst:
            return EmulateVmptrst(vcpu, *instruction);
        case VmxOpcode::Vmread:
            return EmulateVmread(vcpu, *instruction);
        case VmxOpcode::Vmwrite:
            return EmulateVmwrite(vcpu, *instruction);
        case VmxOpcode::Vmlaunch:
            return EmulateVmEntry(vcpu, *instruction, true);
        case VmxOpcode::Vmresume:
            return EmulateVmEntry(vcpu, *instruction, false);
        case VmxOpcode::Invept:
            return EmulateInvept(vcpu, *instruction);
        case VmxOpcode::Invvpid:
            return EmulateInvvpid(vcpu, *instruction);
        case VmxOpcode::Vmfunc:
            return EmulateVmfunc(vcpu, *instruction);
        case VmxOpcode::Vmcall:
            nested_internal::ClearVmInstructionError(vcpu);
            return nested_internal::MakeSuccess(NestedAction::ReflectVmexit,
                                                length, instruction->source);
        default:
            return UndefinedInstruction(*instruction);
    }
}

NestedResult ReflectNestedExit(NestedVcpu* vcpu,
                               const NestedExitRecord* exit_record) {
    if (vcpu == nullptr || exit_record == nullptr ||
        exit_record->version != kNestedModelVersion ||
        exit_record->size < sizeof(NestedExitRecord) ||
        exit_record->size > sizeof(NestedExitRecord) + 64U ||
        exit_record->instruction_length > 15U ||
        vcpu->l2_running == 0) {
        return nested_internal::MakeResult(
            HvStatus::InvalidParameter, NestedAction::QuarantineSession, 0U,
            0U, 0, 0);
    }
    NestedVmcs12* vmcs = nested_internal::CurrentVmcs(vcpu);
    if (vmcs == nullptr) {
        return nested_internal::MakeResult(
            HvStatus::RecoveryRequired, NestedAction::QuarantineSession, 0U,
            exit_record->instruction_length, 0, 0);
    }
    nested_internal::SetVmcsReadOnly(vmcs, kVmcsFieldExitReason,
                                     exit_record->reason);
    nested_internal::SetVmcsReadOnly(vmcs, kVmcsFieldExitQualification,
                                     exit_record->qualification);
    nested_internal::SetVmcsReadOnly(vmcs, 0x440CU,
                                     exit_record->instruction_length);
    vcpu->l2_running = 0;
    ++vcpu->generation;
    return nested_internal::MakeSuccess(NestedAction::ReflectVmexit,
                                        exit_record->instruction_length);
}

}  // namespace knhv
