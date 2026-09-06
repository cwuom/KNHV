#include "test_support.h"

#include "knhv_owner_observation.h"

namespace knhv_tests {
namespace {

knhv::OwnerObservation MakeObservation(knhv::HvOwnerKindV2 owner,
                                       knhv::HvProviderStateV2 state) {
    knhv::OwnerObservation observation = {};
    observation.size = sizeof(observation);
    observation.version = knhv::kOwnerObservationContractVersion;
    observation.cpuid_hypervisor = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    observation.windows_hypervisor = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    observation.vbs = static_cast<std::uint32_t>(knhv::OwnerEvidenceState::Clear);
    observation.hvci = static_cast<std::uint32_t>(knhv::OwnerEvidenceState::Clear);
    observation.whp_available = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    observation.provider_device = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    observation.boot_handoff = static_cast<std::uint32_t>(
        owner == knhv::HvOwnerKindV2::KnhvBootL0
            ? knhv::OwnerEvidenceState::Present
            : knhv::OwnerEvidenceState::Clear);
    observation.provider_owner = static_cast<std::uint32_t>(owner);
    observation.provider_state = static_cast<std::uint32_t>(state);
    observation.generation = 19;
    return observation;
}

void CheckNativeOwnerGate(TestState& state) {
    const knhv::OwnerObservation observation = MakeObservation(
        knhv::HvOwnerKindV2::KnhvBootL0,
        knhv::HvProviderStateV2::Active);
    knhv::OwnerGateResult result = {};
    Check(state, "owner observation accepts complete native handoff evidence",
          knhv::IsOwnerObservationValid(&observation) &&
              knhv::EvaluateOwnerGate(&observation, &result) &&
              knhv::IsOwnerGateResultValid(&result));
    Check(state, "owner gate grants native acquisition only to active KNHV L0",
          result.action == static_cast<std::uint32_t>(
                               knhv::OwnerGateAction::AcquireNative) &&
              result.status == knhv::HvStatus::Success &&
              (result.flags & knhv::kOwnerGateFlagExclusive) != 0 &&
              (result.flags & knhv::kOwnerGateFlagEvidenceComplete) != 0);

    auto missing_handoff = observation;
    missing_handoff.boot_handoff = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    Check(state, "owner gate rejects a KNHV owner without handoff evidence",
          knhv::EvaluateOwnerGate(&missing_handoff, &result) &&
              result.action == static_cast<std::uint32_t>(
                                   knhv::OwnerGateAction::Block) &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::OwnerGateReason::KnhvHandoffMissing) &&
              result.status == knhv::HvStatus::BootHandoffFailed &&
              knhv::IsOwnerGateResultValid(&result));

    auto unknown_vbs = observation;
    unknown_vbs.vbs = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Unknown);
    Check(state, "owner gate fails closed when native VBS evidence is unknown",
          knhv::EvaluateOwnerGate(&unknown_vbs, &result) &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::OwnerGateReason::UnknownOwner) &&
              result.status == knhv::HvStatus::NestedUnavailable);
}

void CheckFallbackOwnerGates(TestState& state) {
    auto external = MakeObservation(knhv::HvOwnerKindV2::ExternalL0,
                                    knhv::HvProviderStateV2::Conflict);
    external.cpuid_hypervisor = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    knhv::OwnerGateResult result = {};
    Check(state, "owner gate classifies an explicit external L0 as fallback",
          knhv::EvaluateOwnerGate(&external, &result) &&
              result.action == static_cast<std::uint32_t>(
                                   knhv::OwnerGateAction::UseExternalProvider) &&
              result.status == knhv::HvStatus::IncompatibleProvider &&
              (result.flags & knhv::kOwnerGateFlagConflict) != 0 &&
              knhv::IsOwnerGateResultValid(&result));

    auto whp = MakeObservation(knhv::HvOwnerKindV2::WhpManaged,
                               knhv::HvProviderStateV2::Available);
    whp.whp_available = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    whp.windows_hypervisor = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    Check(state, "owner gate allows an explicit WHP-managed fallback",
          knhv::EvaluateOwnerGate(&whp, &result) &&
              result.action == static_cast<std::uint32_t>(
                                   knhv::OwnerGateAction::UseWhp) &&
              result.status == knhv::HvStatus::Success &&
              knhv::IsOwnerGateResultValid(&result));

    const auto synthetic = MakeObservation(
        knhv::HvOwnerKindV2::SyntheticLab,
        knhv::HvProviderStateV2::Available);
    Check(state, "owner gate keeps synthetic laboratory mode distinct",
          knhv::EvaluateOwnerGate(&synthetic, &result) &&
              result.action == static_cast<std::uint32_t>(
                                   knhv::OwnerGateAction::UseSynthetic) &&
              result.status == knhv::HvStatus::Success &&
              knhv::IsOwnerGateResultValid(&result));
}

void CheckOwnerGateFailures(TestState& state) {
    knhv::OwnerObservation unknown = {};
    unknown.size = sizeof(unknown);
    unknown.version = knhv::kOwnerObservationContractVersion;
    unknown.cpuid_hypervisor = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    unknown.windows_hypervisor = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Unknown);
    unknown.vbs = static_cast<std::uint32_t>(knhv::OwnerEvidenceState::Unknown);
    unknown.hvci = static_cast<std::uint32_t>(knhv::OwnerEvidenceState::Unknown);
    unknown.whp_available = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Unknown);
    unknown.provider_device = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    unknown.boot_handoff = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Unknown);
    unknown.provider_owner = static_cast<std::uint32_t>(
        knhv::HvOwnerKindV2::Unknown);
    unknown.provider_state = static_cast<std::uint32_t>(
        knhv::HvProviderStateV2::Unknown);
    knhv::OwnerGateResult result = {};
    Check(state, "owner gate blocks an unverified CPUID hypervisor owner",
          knhv::IsOwnerObservationValid(&unknown) &&
              knhv::EvaluateOwnerGate(&unknown, &result) &&
              result.status == knhv::HvStatus::HardwareOwnerConflict &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::OwnerGateReason::ExternalOwnerActive) &&
              knhv::IsOwnerGateResultValid(&result));

    auto contradictory = MakeObservation(knhv::HvOwnerKindV2::ExternalL0,
                                         knhv::HvProviderStateV2::Conflict);
    contradictory.boot_handoff = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    Check(state, "owner gate reports contradictory handoff and external owner",
          knhv::EvaluateOwnerGate(&contradictory, &result) &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::OwnerGateReason::ContradictoryEvidence) &&
              result.status == knhv::HvStatus::HardwareOwnerConflict);

    auto malformed = unknown;
    malformed.provider_device = 9;
    Check(state, "owner observation rejects unknown evidence encodings",
          !knhv::IsOwnerObservationValid(&malformed) &&
              !knhv::EvaluateOwnerGate(&malformed, &result) &&
              result.reason == static_cast<std::uint32_t>(
                                   knhv::OwnerGateReason::InvalidObservation));

    const auto native = MakeObservation(knhv::HvOwnerKindV2::KnhvBootL0,
                                        knhv::HvProviderStateV2::Active);
    Check(state, "owner gate result rejects forged native flags",
          knhv::EvaluateOwnerGate(&native, &result) &&
              knhv::IsOwnerGateResultValid(&result) &&
              ((result.flags ^= knhv::kOwnerGateFlagFallback),
               !knhv::IsOwnerGateResultValid(&result)));
}

}  // namespace

void RunOwnerObservationModelContract(TestState& state) {
    CheckNativeOwnerGate(state);
    CheckFallbackOwnerGates(state);
    CheckOwnerGateFailures(state);
}

}  // namespace knhv_tests
