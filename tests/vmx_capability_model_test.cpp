#include "test_support.h"

#include "knhv_vmx_capability.h"

namespace knhv_tests {
namespace {

knhv::VmxControlCapability PairCapability(std::uint32_t mandatory,
                                           std::uint32_t allowed) {
    knhv::VmxControlCapability capability = {};
    capability.size = sizeof(capability);
    capability.version = knhv::kVmxCapabilityContractVersion;
    capability.encoding = static_cast<std::uint32_t>(
        knhv::VmxControlEncoding::Pair32);
    capability.mandatory_one = mandatory;
    capability.allowed_one = allowed;
    return capability;
}

knhv::VmxControlCapability TertiaryCapability(std::uint64_t allowed) {
    knhv::VmxControlCapability capability = {};
    capability.size = sizeof(capability);
    capability.version = knhv::kVmxCapabilityContractVersion;
    capability.encoding = static_cast<std::uint32_t>(
        knhv::VmxControlEncoding::AllowedOne64);
    capability.allowed_one = allowed;
    return capability;
}

knhv::VmxCapabilitySample MakeSample(std::uint32_t index) {
    knhv::VmxCapabilitySample sample = {};
    sample.size = sizeof(sample);
    sample.version = knhv::kVmxCapabilityContractVersion;
    sample.logical_index = index;
    sample.processor_group = 0;
    sample.processor_number = index;
    sample.status = knhv::kVmxCapabilitySampleCollected;
    sample.generation = 9;
    sample.vmx_basic = 1 | knhv::kVmxBasicTrueControls;
    sample.feature_control = knhv::kVmxFeatureControlLock |
                             knhv::kVmxFeatureControlVmxonOutsideSmx;
    sample.ept_vpid_cap = knhv::kVmxEptVpidCapBasicEpt |
                          knhv::kVmxEptVpidCapFullInvept |
                          knhv::kVmxEptVpidCapFullInvvpid;
    sample.pin_controls = PairCapability(0, 0xFFFFFFFFU);
    sample.primary_controls = PairCapability(
        0, 0xFFFFFFFFU);
    sample.secondary_controls = PairCapability(
        0, 0xFFFFFFFFU);
    sample.tertiary_controls = TertiaryCapability(~0ULL);
    sample.exit_controls = PairCapability(0, 0xFFFFFFFFU);
    sample.entry_controls = PairCapability(0, 0xFFFFFFFFU);
    sample.cr0_fixed0 = 0;
    sample.cr0_fixed1 = ~0ULL;
    sample.cr4_fixed0 = 0;
    sample.cr4_fixed1 = ~0ULL;
    return sample;
}

knhv::VmxControlSet MakeRequest() {
    knhv::VmxControlSet request = {};
    request.size = sizeof(request);
    request.version = knhv::kVmxCapabilityContractVersion;
    request.primary_controls = knhv::kVmxPrimaryActivateSecondary |
                               knhv::kVmxPrimaryActivateTertiary;
    request.secondary_controls = knhv::kVmxSecondaryEnableEpt |
                                 knhv::kVmxSecondaryEnableVpid |
                                 knhv::kVmxSecondaryEnableTscScaling;
    request.tertiary_controls = 1ULL;
    return request;
}

void CheckControlEncoding(TestState& state) {
    auto capability = PairCapability(0x2U, 0x7U);
    Check(state, "VMX pair capability accepts mandatory-one bits",
          knhv::IsVmxControlCapabilityValid(&capability));
    std::uint64_t normalized = 0;
    Check(state, "VMX control normalization adds mandatory bits",
          knhv::NormalizeVmxControlValue(&capability, 0x4, &normalized) &&
              normalized == 0x6 &&
              knhv::IsVmxControlValueAllowed(&capability, normalized));
    Check(state, "VMX pair capability rejects high requested bits",
          !knhv::NormalizeVmxControlValue(&capability, 1ULL << 32,
                                          &normalized));
    auto impossible = PairCapability(0x8U, 0x7U);
    Check(state, "VMX capability rejects mandatory bits outside allowed mask",
          !knhv::IsVmxControlCapabilityValid(&impossible));
    auto tertiary = TertiaryCapability(1ULL << 42);
    Check(state, "VMX tertiary capability uses the 64-bit allowed mask",
          knhv::NormalizeVmxControlValue(&tertiary, 1ULL << 42,
                                         &normalized) &&
              normalized == (1ULL << 42));
    tertiary.mandatory_one = 1;
    Check(state, "VMX tertiary capability rejects mandatory bits",
          !knhv::IsVmxControlCapabilityValid(&tertiary));
}

void CheckSampleContract(TestState& state) {
    auto sample = MakeSample(0);
    Check(state, "VMX capability sample validates with all controls",
          knhv::IsVmxCapabilitySampleValid(&sample) &&
              knhv::IsVmxCapabilitySampleUsable(&sample));
    const std::uint64_t features = knhv::GetVmxCapabilityFeatureFlags(&sample);
    Check(state, "VMX feature derivation includes EPT, VPID, and TSC scaling",
          (features & (knhv::kVmxFeatureEpt | knhv::kVmxFeatureVpid |
                       knhv::kVmxFeatureTscScaling)) ==
              (knhv::kVmxFeatureEpt | knhv::kVmxFeatureVpid |
               knhv::kVmxFeatureTscScaling));

    auto failed = knhv::VmxCapabilitySample{};
    failed.size = sizeof(failed);
    failed.version = knhv::kVmxCapabilityContractVersion;
    failed.logical_index = 1;
    failed.processor_number = 1;
    failed.status = knhv::kVmxCapabilitySampleMsrReadFailed |
                    knhv::kVmxCapabilitySampleOwnerConflict;
    Check(state, "VMX failed sample is valid but unusable",
          knhv::IsVmxCapabilitySampleValid(&failed) &&
              !knhv::IsVmxCapabilitySampleUsable(&failed));

    auto contradictory = sample;
    contradictory.status |= knhv::kVmxCapabilitySampleMsrReadFailed;
    Check(state, "VMX sample rejects collected and failure together",
          !knhv::IsVmxCapabilitySampleValid(&contradictory));
    auto bad_fixed = sample;
    bad_fixed.cr0_fixed0 = 1;
    bad_fixed.cr0_fixed1 = 0;
    Check(state, "VMX sample rejects contradictory fixed CR masks",
          !knhv::IsVmxCapabilitySampleValid(&bad_fixed));
    auto bad_encoding = sample;
    bad_encoding.tertiary_controls.encoding = static_cast<std::uint32_t>(
        knhv::VmxControlEncoding::Pair32);
    Check(state, "VMX sample rejects a tertiary pair encoding",
          !knhv::IsVmxCapabilitySampleValid(&bad_encoding));
}

void CheckControlDependencies(TestState& state) {
    const auto sample = MakeSample(0);
    const auto request = MakeRequest();
    knhv::VmxControlSet normalized = {};
    Check(state, "VMX control set normalizes with explicit dependencies",
          knhv::NormalizeVmxControlSet(&sample, &request, &normalized) &&
              (normalized.primary_controls &
               knhv::kVmxPrimaryActivateSecondary) != 0 &&
              (normalized.secondary_controls & knhv::kVmxSecondaryEnableEpt) !=
                  0);

    auto missing_primary = request;
    missing_primary.primary_controls = knhv::kVmxPrimaryActivateTertiary;
    Check(state, "VMX control set rejects secondary controls without activation",
          !knhv::NormalizeVmxControlSet(&sample, &missing_primary,
                                        &normalized));
    auto missing_ept = sample;
    missing_ept.ept_vpid_cap &= ~knhv::kVmxEptVpidCapBasicEpt;
    Check(state, "VMX control set rejects EPT without basic EPT capability",
          !knhv::NormalizeVmxControlSet(&missing_ept, &request, &normalized));
    auto missing_vpid = sample;
    missing_vpid.ept_vpid_cap &= ~knhv::kVmxEptVpidCapInvvpid;
    Check(state, "VMX control set rejects VPID without INVVPID",
          !knhv::NormalizeVmxControlSet(&missing_vpid, &request,
                                        &normalized));
    auto unlocked = sample;
    unlocked.feature_control &= ~knhv::kVmxFeatureControlLock;
    Check(state, "VMX control set rejects an unlocked feature-control MSR",
          !knhv::NormalizeVmxControlSet(&unlocked, &request, &normalized));
}

void CheckMatrixContract(TestState& state) {
    knhv::VmxCapabilitySample samples[2] = {MakeSample(0), MakeSample(1)};
    knhv::VmxCapabilityMatrix matrix = {};
    Check(state, "VMX capability matrix builds a uniform result",
          knhv::BuildVmxCapabilityMatrix(samples, 2, 2, &matrix) &&
              matrix.state == static_cast<std::uint32_t>(
                  knhv::VmxCapabilityMatrixState::CompleteUniform) &&
              knhv::IsVmxCapabilityMatrixUniform(
                  &matrix, knhv::kVmxFeatureEpt | knhv::kVmxFeatureVpid,
                  knhv::kVmxEptVpidCapBasicEpt));
    samples[1].ept_vpid_cap &= ~knhv::kVmxEptVpidCapInvvpidRetainGlobals;
    Check(state, "VMX capability matrix reports mixed EPT capabilities",
          knhv::BuildVmxCapabilityMatrix(samples, 2, 2, &matrix) &&
              matrix.state == static_cast<std::uint32_t>(
                  knhv::VmxCapabilityMatrixState::CompleteMixed) &&
              !knhv::IsVmxCapabilityMatrixUniform(&matrix, 0, 0));

    auto failed = knhv::VmxCapabilitySample{};
    failed.size = sizeof(failed);
    failed.version = knhv::kVmxCapabilityContractVersion;
    failed.logical_index = 1;
    failed.processor_number = 1;
    failed.status = knhv::kVmxCapabilitySampleOwnerConflict;
    samples[1] = failed;
    Check(state, "VMX capability matrix keeps owner failures incomplete",
          knhv::BuildVmxCapabilityMatrix(samples, 2, 2, &matrix) &&
              matrix.state == static_cast<std::uint32_t>(
                  knhv::VmxCapabilityMatrixState::Incomplete) &&
              matrix.invalid_count == 1);

    samples[1] = samples[0];
    Check(state, "VMX capability matrix rejects duplicate processor identity",
          !knhv::BuildVmxCapabilityMatrix(samples, 2, 2, &matrix));
    Check(state, "VMX capability matrix rejects an oversized expectation",
          !knhv::BuildVmxCapabilityMatrix(samples, 0,
                                          knhv::kVmxCapabilityMaxProcessors + 1,
                                          &matrix));

    samples[1] = MakeSample(1);
    Check(state, "VMX capability matrix summary validates its flags",
          knhv::BuildVmxCapabilityMatrix(samples, 2, 2, &matrix) &&
              knhv::IsVmxCapabilityMatrixValid(&matrix));
    matrix.flags ^= knhv::kVmxMatrixAllVmx;
    Check(state, "VMX capability matrix rejects forged summary flags",
          !knhv::IsVmxCapabilityMatrixValid(&matrix));
}

}  // namespace

void RunVmxCapabilityModelContract(TestState& state) {
    CheckControlEncoding(state);
    CheckSampleContract(state);
    CheckControlDependencies(state);
    CheckMatrixContract(state);
}

}  // namespace knhv_tests
