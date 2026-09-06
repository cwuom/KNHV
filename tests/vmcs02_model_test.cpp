#include "test_support.h"

#include "knhv_vmcs02.h"

namespace knhv_tests {
namespace {

knhv::Vmcs12Model MakeVmcs12(const knhv::NestedCapabilities& capabilities) {
    knhv::Vmcs12Model model = {};
    model.size = sizeof(model);
    model.version = knhv::kVmcs02ModelVersion;
    model.revision = capabilities.vmx_revision;
    model.state = static_cast<std::uint32_t>(knhv::Vmcs12State::Active);
    model.primary_controls = knhv::kVmcs02PrimaryActivateSecondary;
    model.secondary_controls = knhv::kNestedSecondaryEnableEpt |
                               knhv::kNestedSecondaryEnableVpid;
    model.guest_cr3 = 0x2000;
    model.guest_rip = 0x100000;
    model.guest_rsp = 0x200000;
    model.guest_rflags = 2;
    model.ept_pointer = 0x5000 | 6ULL | (3ULL << 3);
    model.vpid = 1;
    return model;
}

knhv::Vmcs02Policy MakePolicy() {
    knhv::Vmcs02Policy policy = {};
    policy.size = sizeof(policy);
    policy.version = knhv::kVmcs02ModelVersion;
    policy.required_primary_controls = knhv::kVmcs02PrimaryActivateSecondary;
    policy.required_exit_controls = 1U;
    policy.required_secondary_controls = knhv::kNestedSecondaryEnableEpt;
    policy.host_cr3 = 0x7000;
    policy.host_rip = 0x300000;
    policy.host_rsp = 0x400000;
    policy.ept_pointer = 0x9000 | 6ULL | (3ULL << 3);
    policy.io_bitmap_a = 0xA000;
    policy.io_bitmap_b = 0xB000;
    policy.msr_bitmap = 0xC000;
    policy.generation = 3;
    return policy;
}

void CheckVmcs02Build(TestState& state) {
    knhv::NestedCapabilities capabilities = {};
    knhv::InitializeNestedCapabilities(&capabilities);
    knhv::Vmcs12Model vmcs12 = MakeVmcs12(capabilities);
    knhv::Vmcs02Policy policy = MakePolicy();
    knhv::Vmcs02Image image = {};
    const knhv::Vmcs02BuildStatus status =
        knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image);
    Check(state, "VMCS02 model applies the L0 policy and succeeds",
          status == knhv::Vmcs02BuildStatus::Success &&
              image.status == static_cast<std::uint32_t>(
                  knhv::Vmcs02BuildStatus::Success));
    Check(state, "VMCS02 model preserves guest state and policy generation",
          image.guest_cr3 == vmcs12.guest_cr3 &&
              image.guest_rip == vmcs12.guest_rip &&
              image.host_cr3 == policy.host_cr3 &&
              image.generation == policy.generation);
    Check(state, "VMCS02 model validates the resulting image",
          knhv::IsVmcs02ImageValid(&image, &capabilities, &policy));
    Check(state, "VMCS02 model carries EPT and merged control bits",
          image.ept_pointer == policy.ept_pointer &&
              (image.primary_controls & knhv::kVmcs02PrimaryActivateSecondary) !=
                  0 &&
              (image.exit_controls & policy.required_exit_controls) != 0);
}

void CheckVmcs02Failures(TestState& state) {
    knhv::NestedCapabilities capabilities = {};
    knhv::InitializeNestedCapabilities(&capabilities);
    knhv::Vmcs12Model vmcs12 = MakeVmcs12(capabilities);
    knhv::Vmcs02Policy policy = MakePolicy();
    knhv::Vmcs02Image image = {};
    vmcs12.primary_controls &= ~knhv::kVmcs02PrimaryActivateSecondary;
    policy.required_secondary_controls = 0;
    policy.required_primary_controls = 0;
    capabilities.primary_allowed1 &= ~knhv::kVmcs02PrimaryActivateSecondary;
    Check(state, "VMCS02 model rejects a secondary-control dependency",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::CapabilityMismatch);

    knhv::InitializeNestedCapabilities(&capabilities);
    vmcs12 = MakeVmcs12(capabilities);
    vmcs12.ept_pointer = 0x5000;
    Check(state, "VMCS02 model rejects an invalid EPTP encoding",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::Vmcs12Invalid);

    knhv::InitializeNestedCapabilities(&capabilities);
    vmcs12 = MakeVmcs12(capabilities);
    policy = MakePolicy();
    policy.forbidden_exit_controls = policy.required_exit_controls;
    Check(state, "VMCS02 model rejects contradictory policy controls",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::InvalidParameter);

    knhv::InitializeNestedCapabilities(&capabilities);
    vmcs12 = MakeVmcs12(capabilities);
    policy = MakePolicy();
    policy.generation = 0;
    Check(state, "VMCS02 model rejects a zero policy generation",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::InvalidParameter);

    knhv::InitializeNestedCapabilities(&capabilities);
    vmcs12 = MakeVmcs12(capabilities);
    policy = MakePolicy();
    vmcs12.guest_cr3 = 1ULL << 52;
    Check(state, "VMCS02 model rejects a guest CR3 outside the PA width",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::Vmcs12Invalid);
}

void CheckVmcs02InputBoundaries(TestState& state) {
    knhv::NestedCapabilities capabilities = {};
    knhv::InitializeNestedCapabilities(&capabilities);
    knhv::Vmcs12Model vmcs12 = MakeVmcs12(capabilities);
    knhv::Vmcs02Policy policy = MakePolicy();
    knhv::Vmcs02Image image = {};
    vmcs12.size = sizeof(vmcs12) - 1U;
    Check(state, "VMCS02 model rejects a truncated VMCS12 view",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::Vmcs12Invalid);
    vmcs12 = MakeVmcs12(capabilities);
    policy.size = knhv::kVmcs02MaxStructSize + 1U;
    Check(state, "VMCS02 model rejects an oversized policy contract",
          knhv::BuildVmcs02Model(&vmcs12, &capabilities, &policy, &image) ==
              knhv::Vmcs02BuildStatus::InvalidParameter);
    std::uint64_t next = 0;
    Check(state, "VMCS02 model does not wrap a generation counter",
          !knhv::NextEptGeneration(~0ULL, &next));
}

}  // namespace

void RunVmcs02ModelContract(TestState& state) {
    CheckVmcs02Build(state);
    CheckVmcs02Failures(state);
    CheckVmcs02InputBoundaries(state);
}

}  // namespace knhv_tests
