#include "test_support.h"

#include "knhv_nested.h"
#include "knhv_provider.h"
#include "knhv_boot_contract.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace knhv_tests {
namespace {

struct TestMemory {
    bool remap = false;
    bool reject_vmxon_middle = false;
    std::array<std::uint8_t, 64U * 1024U> bytes{};
};

constexpr std::uint64_t kVmxonOperandLinear = 0x100U;
constexpr std::uint64_t kVmcsOperandLinear = 0x108U;
constexpr std::uint64_t kVmxonRegionGpa = 0x2000U;
constexpr std::uint64_t kVmcsRegionGpa = 0x3000U;
constexpr std::uint32_t kVmxRevision = 1U;

void WriteU64(TestMemory& memory, std::uint64_t offset,
              std::uint64_t value) {
    std::memcpy(memory.bytes.data() + offset, &value, sizeof(value));
}

void InitializeVmxOperands(TestMemory& memory,
                           std::uint64_t vmxon_region,
                           std::uint64_t vmcs_region) {
    WriteU64(memory, kVmxonOperandLinear, vmxon_region);
    WriteU64(memory, kVmcsOperandLinear, vmcs_region);
    std::memcpy(memory.bytes.data() + vmxon_region, &kVmxRevision,
                sizeof(kVmxRevision));
    std::memcpy(memory.bytes.data() + vmcs_region, &kVmxRevision,
                sizeof(kVmxRevision));
}

std::uint64_t MapLinear(const TestMemory& memory, std::uint64_t linear) {
    if (!memory.remap) return linear;
    const std::uint64_t page = linear / 0x1000U;
    const std::uint64_t offset = linear & 0xFFFU;
    const std::uint64_t physical_page = page == 0 ? 8U :
                                        page == 1 ? 9U : page;
    return physical_page * 0x1000U + offset;
}

bool Translate(void* context, std::uint64_t linear,
               std::uint64_t* physical, std::uint32_t access) {
    auto* memory = static_cast<TestMemory*>(context);
    if (memory == nullptr || physical == nullptr || access == 0 ||
        linear >= memory->bytes.size()) {
        return false;
    }
    *physical = MapLinear(*memory, linear);
    return *physical < memory->bytes.size();
}

bool Read(void* context, std::uint64_t physical, void* destination,
          std::uint32_t length) {
    auto* memory = static_cast<TestMemory*>(context);
    if (memory == nullptr || destination == nullptr || length == 0 ||
        physical >= memory->bytes.size() ||
        length > memory->bytes.size() - static_cast<std::size_t>(physical)) {
        return false;
    }
    if (memory->reject_vmxon_middle &&
        physical >= kVmxonRegionGpa + 0x100U &&
        physical < kVmxonRegionGpa + 0x140U) {
        return false;
    }
    std::memcpy(destination, memory->bytes.data() + physical, length);
    return true;
}

bool Write(void* context, std::uint64_t physical, const void* source,
           std::uint32_t length) {
    auto* memory = static_cast<TestMemory*>(context);
    if (memory == nullptr || source == nullptr || length == 0 ||
        physical >= memory->bytes.size() ||
        length > memory->bytes.size() - static_cast<std::size_t>(physical)) {
        return false;
    }
    std::memcpy(memory->bytes.data() + physical, source, length);
    return true;
}

knhv::VmxInstruction Instruction(knhv::VmxOpcode opcode) {
    knhv::VmxInstruction instruction = {};
    instruction.version = knhv::kNestedModelVersion;
    instruction.size = sizeof(instruction);
    instruction.opcode = opcode;
    instruction.instruction_length = 3;
    return instruction;
}

void SetEntryState(knhv::NestedVcpu& vcpu) {
    const std::uint32_t primary = 1U << 31;
    const std::uint32_t secondary = knhv::kNestedSecondaryEnableEpt;
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldPinControls, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldPrimaryControls,
                               primary);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldSecondaryControls,
                               secondary);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldExitControls, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldEntryControls, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldGuestCr0, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldGuestCr3, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldGuestCr4, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldHostCr0, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldHostCr3, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldHostCr4, 0);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldGuestRip, 0x1000);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldGuestRsp, 0x2000);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldHostRip, 0x3000);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldHostRsp, 0x4000);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldGuestRflags, 2);
    knhv::WriteNestedVmcsField(&vcpu, knhv::kVmcsFieldEptPointer, 0x5000);
}

void CheckProviderSelection(TestState& state) {
    knhv::HvCapabilitySnapshot snapshot = {};
    snapshot.version = knhv::kAbiVersion;
    snapshot.size = sizeof(snapshot);
    snapshot.feature_bits = knhv::kCapVmx | knhv::kCapEpt |
                            knhv::kCapVpid | knhv::kCapNestedVmx |
                            knhv::kCapWhpPartition | knhv::kCapBootL0;
    snapshot.status_flags = knhv::kFlagKnhvBootL0Active |
                            knhv::kFlagNestedVmx |
                            knhv::kFlagWhpPartition |
                            knhv::kFlagNativeVmxReady |
                            knhv::kFlagBootHandoffVerified;
    snapshot.max_physical_address_bits = 48;
    knhv::HvProviderRequest request = {};
    request.version = knhv::kAbiVersion;
    request.size = sizeof(request);
    request.mode = knhv::HvMode::CooperativeL1;
    request.identity_verified = 1;
    knhv::HvProviderKind selected = knhv::HvProviderKind::None;
    Check(state, "cooperative provider requires the KNHV L0 contract",
          knhv::SelectProvider(&request, &snapshot, &selected) ==
              knhv::HvStatus::Success &&
              selected == knhv::HvProviderKind::CooperativeL1);

    snapshot.status_flags &= ~knhv::kFlagKnhvBootL0Active;
    Check(state, "cooperative provider is unavailable without BootL0",
          knhv::SelectProvider(&request, &snapshot, &selected) ==
              knhv::HvStatus::NestedUnavailable);

    request.mode = knhv::HvMode::KnownLegacyCompat;
    request.legacy_manifest_match = 0;
    Check(state, "unknown legacy clients degrade to load-only",
          knhv::SelectProvider(&request, &snapshot, &selected) ==
              knhv::HvStatus::LoadOnly &&
              selected == knhv::HvProviderKind::LoadOnly);

    knhv::HvCapabilitySnapshot malformed = snapshot;
    malformed.feature_bits |= 1ULL << 63;
    Check(state, "provider selection rejects unknown capability bits",
          knhv::SelectProvider(&request, &malformed, &selected) ==
              knhv::HvStatus::InvalidParameter);
}

void CheckBootContract(TestState& state) {
    knhv::BootL0Contract contract = {};
    knhv::InitializeBootL0Contract(&contract);
    knhv::BootContext context = {};
    context.version = knhv::kAbiVersion;
    context.size = sizeof(context);
    context.logical_processors = 2;
    context.manifest_valid = 1;
    context.physical_vmx_ready = 1;
    context.windows_handoff_ready = 1;
    Check(state, "BootL0 contract starts with one physical owner",
          knhv::StartBootL0(&contract, &context) == knhv::HvStatus::Success &&
              contract.owner.owner_count == 1 &&
              contract.owner.active_processors == 2);
    Check(state, "BootL0 contract publishes a ready Windows handoff",
          knhv::HandoffWindows(&contract, &context) == knhv::HvStatus::Success &&
              contract.state == knhv::BootL0State::Ready);
    Check(state, "BootL0 contract rejects a competing owner",
          knhv::StartBootL0(&contract, &context) == knhv::HvStatus::Busy);
    Check(state, "BootL0 recovery invalidates the owner token",
          knhv::RecoverBootL0(&contract, knhv::HvStatus::RecoveryRequired) ==
              knhv::HvStatus::RecoveryRequired &&
              contract.owner.owner_count == 0);
    context.external_owner = 1;
    Check(state, "BootL0 contract records an external owner conflict",
          knhv::StartBootL0(&contract, &context) ==
              knhv::HvStatus::HardwareOwnerConflict &&
              contract.state == knhv::BootL0State::Recovery);
}

}  // namespace

void RunNestedModelContract(const fs::path& root, TestState& state) {
    (void)root;
    CheckProviderSelection(state);
    CheckBootContract(state);

    TestMemory memory;
    InitializeVmxOperands(memory, kVmxonRegionGpa, kVmcsRegionGpa);
    knhv::NestedMemory callbacks = {};
    callbacks.context = &memory;
    callbacks.translate = Translate;
    callbacks.read = Read;
    callbacks.write = Write;
    knhv::NestedCapabilities capabilities = {};
    knhv::InitializeNestedCapabilities(&capabilities);
    knhv::NestedVcpu vcpu = {};
    knhv::InitializeNestedVcpu(&vcpu, &capabilities, &callbacks);
    vcpu.vmxe_enabled = 1;

    std::uint32_t invalid_revision = 0x80000001U;
    std::memcpy(memory.bytes.data() + kVmxonRegionGpa, &invalid_revision,
                sizeof(invalid_revision));
    knhv::VmxInstruction invalid_instruction =
        Instruction(knhv::VmxOpcode::Vmxon);
    invalid_instruction.linear_operand = kVmxonOperandLinear;
    knhv::NestedResult result =
        knhv::DispatchNestedInstruction(&vcpu, &invalid_instruction);
    Check(state, "nested VMXON rejects a revision with bit 31 set",
          result.status == knhv::HvStatus::VmfailInvalid &&
              (result.rflags & knhv::kRflagsCarry) != 0 &&
              (result.rflags & knhv::kRflagsZero) == 0 &&
              result.instruction_error == 0);
    InitializeVmxOperands(memory, kVmxonRegionGpa, kVmcsRegionGpa);

    knhv::VmxInstruction instruction = Instruction(knhv::VmxOpcode::Vmxon);
    instruction.linear_operand = kVmxonOperandLinear;
    result =
        knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "nested VMXON accepts a translated aligned region",
          result.status == knhv::HvStatus::Success &&
              vcpu.vmxon_active != 0 &&
              vcpu.vmxon_gpa == kVmxonRegionGpa);

    TestMemory partial_memory;
    partial_memory.reject_vmxon_middle = true;
    InitializeVmxOperands(partial_memory, kVmxonRegionGpa, kVmcsRegionGpa);
    knhv::NestedMemory partial_callbacks = {};
    partial_callbacks.context = &partial_memory;
    partial_callbacks.translate = Translate;
    partial_callbacks.read = Read;
    partial_callbacks.write = Write;
    knhv::NestedVcpu partial_vcpu = {};
    knhv::InitializeNestedVcpu(&partial_vcpu, &capabilities,
                               &partial_callbacks);
    partial_vcpu.vmxe_enabled = 1;
    knhv::VmxInstruction partial_instruction =
        Instruction(knhv::VmxOpcode::Vmxon);
    partial_instruction.linear_operand = kVmxonOperandLinear;
    const knhv::NestedResult partial_result =
        knhv::DispatchNestedInstruction(&partial_vcpu, &partial_instruction);
    Check(state, "nested VMXON rejects a partially unreadable region",
          partial_result.status == knhv::HvStatus::VmfailInvalid &&
              partial_vcpu.vmxon_active == 0);

    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "nested VMXON reports VMfailValid when already active",
          result.status == knhv::HvStatus::VmfailValid &&
              (result.rflags & knhv::kRflagsZero) != 0 &&
              (result.rflags & knhv::kRflagsCarry) == 0);

    instruction = Instruction(knhv::VmxOpcode::Vmptrld);
    instruction.linear_operand = kVmcsOperandLinear;
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMPTRLD establishes a software VMCS12 current pointer",
          result.status == knhv::HvStatus::Success &&
              vcpu.current_vmcs_gpa == kVmcsRegionGpa);
    SetEntryState(vcpu);

    instruction = Instruction(knhv::VmxOpcode::Vmlaunch);
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMLAUNCH enters the modeled L2 state",
          result.status == knhv::HvStatus::Success &&
              result.action == knhv::NestedAction::EnterL2 &&
              vcpu.l2_running != 0);

    instruction = Instruction(knhv::VmxOpcode::Vmclear);
    instruction.linear_operand = kVmcsOperandLinear;
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMCLEAR is rejected while L2 is running",
          result.status == knhv::HvStatus::Busy &&
              vcpu.current_vmcs_gpa == kVmcsRegionGpa);

    knhv::NestedExitRecord exit_record = {};
    exit_record.version = knhv::kNestedModelVersion;
    exit_record.size = sizeof(exit_record);
    exit_record.reason = 10;
    exit_record.instruction_length = 2;
    exit_record.qualification = 0x1234;
    result = knhv::ReflectNestedExit(&vcpu, &exit_record);
    std::uint64_t exit_reason = 0;
    Check(state, "L2 exits are reflected into VMCS12",
          result.status == knhv::HvStatus::Success &&
              knhv::ReadNestedVmcsField(&vcpu, knhv::kVmcsFieldExitReason,
                                        &exit_reason) &&
              exit_reason == 10 && vcpu.l2_running == 0);

    instruction = Instruction(knhv::VmxOpcode::Vmresume);
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMRESUME re-enters a launched VMCS12",
          result.status == knhv::HvStatus::Success && vcpu.l2_running != 0);

    exit_record.reason = 12;
    result = knhv::ReflectNestedExit(&vcpu, &exit_record);
    Check(state, "a second exit returns control to L1",
          result.status == knhv::HvStatus::Success && vcpu.l2_running == 0);

    instruction = Instruction(knhv::VmxOpcode::Vmlaunch);
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMLAUNCH rejects an already launched VMCS with VMfailValid",
          result.status == knhv::HvStatus::VmfailValid &&
              result.instruction_error == 4 &&
              (result.rflags & knhv::kRflagsZero) != 0 &&
              (result.rflags & knhv::kRflagsCarry) == 0);

    instruction = Instruction(knhv::VmxOpcode::Vmread);
    instruction.flags = knhv::kInstructionOperandIsRegister;
    instruction.encoding = knhv::kVmcsFieldGuestRip;
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMREAD returns the requested field value",
          result.status == knhv::HvStatus::Success && result.value == 0x1000);

    instruction = Instruction(knhv::VmxOpcode::Vmptrst);
    instruction.destination = 0x0001000000000000ULL;
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMPTRST rejects a noncanonical destination",
          result.status == knhv::HvStatus::VmfailInvalid &&
              (result.rflags & knhv::kRflagsCarry) != 0);

    instruction = Instruction(knhv::VmxOpcode::Vmclear);
    instruction.linear_operand = kVmcsOperandLinear;
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMCLEAR removes the current VMCS12",
          result.status == knhv::HvStatus::Success &&
              vcpu.current_vmcs_gpa == ~0ULL);

    instruction = Instruction(knhv::VmxOpcode::Vmresume);
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMRESUME without a current VMCS reports VMfailInvalid",
          result.status == knhv::HvStatus::VmfailInvalid &&
              result.instruction_error == 0 &&
              (result.rflags & knhv::kRflagsCarry) != 0);

    instruction = Instruction(static_cast<knhv::VmxOpcode>(99));
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "unknown VMX encodings inject a virtual undefined instruction",
          result.status == knhv::HvStatus::VirtualUnsupported &&
              result.action == knhv::NestedAction::InjectUndefinedInstruction);

    instruction = Instruction(knhv::VmxOpcode::Vmxoff);
    result = knhv::DispatchNestedInstruction(&vcpu, &instruction);
    Check(state, "VMXOFF returns to the L1 execution context",
          result.status == knhv::HvStatus::Success &&
              vcpu.vmxon_active == 0);

    TestMemory remapped_memory;
    remapped_memory.remap = true;
    const std::uint64_t vmxon_physical = 0x8000;
    const std::uint64_t vmcs_physical = 0x9000;
    WriteU64(remapped_memory, 0x8100, vmxon_physical);
    WriteU64(remapped_memory, 0x8108, vmcs_physical);
    std::memcpy(remapped_memory.bytes.data() + vmxon_physical, &kVmxRevision,
                sizeof(kVmxRevision));
    std::memcpy(remapped_memory.bytes.data() + vmcs_physical, &kVmxRevision,
                sizeof(kVmxRevision));
    knhv::NestedMemory remapped_callbacks = {};
    remapped_callbacks.context = &remapped_memory;
    remapped_callbacks.translate = Translate;
    remapped_callbacks.read = Read;
    remapped_callbacks.write = Write;
    knhv::NestedVcpu remapped_vcpu = {};
    knhv::InitializeNestedVcpu(&remapped_vcpu, &capabilities,
                               &remapped_callbacks);
    remapped_vcpu.vmxe_enabled = 1;
    instruction = Instruction(knhv::VmxOpcode::Vmxon);
    instruction.linear_operand = kVmxonOperandLinear;
    result = knhv::DispatchNestedInstruction(&remapped_vcpu, &instruction);
    instruction = Instruction(knhv::VmxOpcode::Vmptrld);
    instruction.linear_operand = kVmcsOperandLinear;
    result = knhv::DispatchNestedInstruction(&remapped_vcpu, &instruction);
    instruction = Instruction(knhv::VmxOpcode::Vmptrst);
    instruction.destination = 0x0FFC;
    result = knhv::DispatchNestedInstruction(&remapped_vcpu, &instruction);
    std::uint64_t stored_pointer = 0;
    std::memcpy(&stored_pointer, remapped_memory.bytes.data() + 0x8FFC,
                sizeof(std::uint32_t));
    std::memcpy(reinterpret_cast<std::uint8_t*>(&stored_pointer) + 4,
                remapped_memory.bytes.data() + 0x9000, sizeof(std::uint32_t));
    Check(state, "linear page crossings preserve translated GPA semantics",
          result.status == knhv::HvStatus::Success &&
              stored_pointer == vmcs_physical);

    TestMemory second_memory;
    InitializeVmxOperands(second_memory, kVmxonRegionGpa, kVmcsRegionGpa);
    knhv::NestedMemory second_callbacks = {};
    second_callbacks.context = &second_memory;
    second_callbacks.translate = Translate;
    second_callbacks.read = Read;
    second_callbacks.write = Write;
    knhv::NestedVcpu second_vcpu = {};
    knhv::InitializeNestedVcpu(&second_vcpu, &capabilities,
                               &second_callbacks);
    second_vcpu.vmxe_enabled = 1;
    instruction = Instruction(knhv::VmxOpcode::Vmxon);
    instruction.linear_operand = kVmxonOperandLinear;
    result = knhv::DispatchNestedInstruction(&second_vcpu, &instruction);
    Check(state, "independent vCPU state does not leak across clients",
          result.status == knhv::HvStatus::Success &&
              second_vcpu.vmxon_active != 0 && vcpu.vmxon_active == 0);
}

}  // namespace knhv_tests
