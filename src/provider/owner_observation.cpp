#include "knhv_owner_observation.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kOwnerObservationContractVersion &&
           size >= required && size <= kOwnerObservationMaxStructSize;
}

bool IsEvidenceStateValid(u32 value) {
    return value <= static_cast<u32>(OwnerEvidenceState::Present);
}

bool IsOwnerKindValid(u32 value) {
    return value <= static_cast<u32>(HvOwnerKindV2::SyntheticLab);
}

bool IsProviderStateValid(u32 value) {
    return value <= static_cast<u32>(HvProviderStateV2::Quarantined);
}

bool IsStatusValid(HvStatus status) {
    return static_cast<u32>(status) <= static_cast<u32>(HvStatus::Busy);
}

bool IsActionValid(u32 value) {
    return value <= static_cast<u32>(OwnerGateAction::UseSynthetic);
}

bool IsReasonValid(u32 value) {
    return value <= static_cast<u32>(OwnerGateReason::ProviderStateInvalid);
}

bool IsPresent(const OwnerObservation& observation,
               u32 OwnerObservation::*member) {
    return observation.*member ==
           static_cast<u32>(OwnerEvidenceState::Present);
}

bool IsClear(const OwnerObservation& observation,
             u32 OwnerObservation::*member) {
    return observation.*member ==
           static_cast<u32>(OwnerEvidenceState::Clear);
}

bool HasNativeEvidence(const OwnerObservation& observation) {
    return IsClear(observation, &OwnerObservation::cpuid_hypervisor) &&
           IsClear(observation, &OwnerObservation::windows_hypervisor) &&
           IsClear(observation, &OwnerObservation::vbs) &&
           IsClear(observation, &OwnerObservation::hvci) &&
           IsPresent(observation, &OwnerObservation::provider_device) &&
           IsPresent(observation, &OwnerObservation::boot_handoff);
}

bool IsNativeOwner(const OwnerObservation& observation) {
    return observation.provider_owner ==
           static_cast<u32>(HvOwnerKindV2::KnhvBootL0);
}

bool IsExternalOwner(const OwnerObservation& observation) {
    return observation.provider_owner ==
           static_cast<u32>(HvOwnerKindV2::ExternalL0);
}

bool IsWhpOwner(const OwnerObservation& observation) {
    return observation.provider_owner ==
           static_cast<u32>(HvOwnerKindV2::WhpManaged);
}

bool IsSyntheticOwner(const OwnerObservation& observation) {
    return observation.provider_owner ==
           static_cast<u32>(HvOwnerKindV2::SyntheticLab);
}

bool IsAvailableOrActive(const OwnerObservation& observation) {
    return observation.provider_state ==
               static_cast<u32>(HvProviderStateV2::Available) ||
           observation.provider_state ==
               static_cast<u32>(HvProviderStateV2::Active);
}

bool HasContradictoryEvidence(const OwnerObservation& observation) {
    if (IsPresent(observation, &OwnerObservation::boot_handoff) &&
        !IsNativeOwner(observation)) {
        return true;
    }
    if (IsNativeOwner(observation) &&
        (IsPresent(observation, &OwnerObservation::cpuid_hypervisor) ||
         IsPresent(observation, &OwnerObservation::windows_hypervisor) ||
         observation.provider_state ==
             static_cast<u32>(HvProviderStateV2::Conflict) ||
         observation.provider_state ==
             static_cast<u32>(HvProviderStateV2::Quarantined))) {
        return true;
    }
    return IsExternalOwner(observation) &&
           observation.provider_state !=
               static_cast<u32>(HvProviderStateV2::Conflict) &&
           observation.provider_state !=
               static_cast<u32>(HvProviderStateV2::Active);
}

void InitializeResult(OwnerGateResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kOwnerObservationContractVersion;
    result->action = static_cast<u32>(OwnerGateAction::Block);
    result->reason = static_cast<u32>(OwnerGateReason::InvalidObservation);
    result->status = HvStatus::InvalidParameter;
}

void SetResult(OwnerGateResult* result, OwnerGateAction action,
               OwnerGateReason reason, HvStatus status, HvOwnerKindV2 owner,
               u32 flags, u64 generation) {
    result->action = static_cast<u32>(action);
    result->reason = static_cast<u32>(reason);
    result->status = status;
    result->owner = static_cast<u32>(owner);
    result->flags = flags;
    result->generation = generation;
}

bool IsBlockedResultConsistent(const OwnerGateResult& result) {
    return result.action == static_cast<u32>(OwnerGateAction::Block) &&
           result.status != HvStatus::Success &&
           result.reason != static_cast<u32>(OwnerGateReason::None) &&
           (result.flags & (kOwnerGateFlagExclusive |
                            kOwnerGateFlagFallback)) == 0;
}

}  // namespace

bool IsOwnerObservationValid(const OwnerObservation* observation) {
    if (observation == nullptr ||
        !IsVersionedSizeValid(observation->version, observation->size,
                              sizeof(OwnerObservation)) ||
        !IsEvidenceStateValid(observation->cpuid_hypervisor) ||
        !IsEvidenceStateValid(observation->windows_hypervisor) ||
        !IsEvidenceStateValid(observation->vbs) ||
        !IsEvidenceStateValid(observation->hvci) ||
        !IsEvidenceStateValid(observation->whp_available) ||
        !IsEvidenceStateValid(observation->provider_device) ||
        !IsEvidenceStateValid(observation->boot_handoff) ||
        !IsOwnerKindValid(observation->provider_owner) ||
        !IsProviderStateValid(observation->provider_state) ||
        observation->reserved != 0) {
        return false;
    }
    const bool provider_known =
        observation->provider_owner != static_cast<u32>(HvOwnerKindV2::Unknown) ||
        observation->provider_state !=
            static_cast<u32>(HvProviderStateV2::Unknown);
    if (provider_known &&
        observation->provider_device !=
            static_cast<u32>(OwnerEvidenceState::Present)) {
        return false;
    }
    return observation->provider_state !=
               static_cast<u32>(HvProviderStateV2::Active) ||
           (observation->provider_owner !=
                static_cast<u32>(HvOwnerKindV2::Unknown) &&
            observation->generation != 0);
}

bool EvaluateOwnerGate(const OwnerObservation* observation,
                       OwnerGateResult* result) {
    if (result == nullptr) return false;
    InitializeResult(result);
    if (!IsOwnerObservationValid(observation)) return false;

    const OwnerObservation& input = *observation;
    const auto owner = static_cast<HvOwnerKindV2>(input.provider_owner);
    result->owner = input.provider_owner;
    result->generation = input.generation;
    if (HasContradictoryEvidence(input)) {
        SetResult(result, OwnerGateAction::Block,
                  OwnerGateReason::ContradictoryEvidence,
                  HvStatus::HardwareOwnerConflict, owner,
                  kOwnerGateFlagConflict, input.generation);
        return true;
    }

    if (IsNativeOwner(input)) {
        if (!IsPresent(input, &OwnerObservation::provider_device)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::ProviderUnavailable,
                      HvStatus::NestedUnavailable, owner, 0, input.generation);
        } else if (input.generation == 0) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::GenerationMissing,
                      HvStatus::BootHandoffFailed, owner, 0, input.generation);
        } else if (!IsPresent(input, &OwnerObservation::boot_handoff)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::KnhvHandoffMissing,
                      HvStatus::BootHandoffFailed, owner, 0, input.generation);
        } else if (input.provider_state !=
                   static_cast<u32>(HvProviderStateV2::Active)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::ProviderStateInvalid,
                      HvStatus::BootHandoffFailed, owner, 0, input.generation);
        } else if (IsPresent(input, &OwnerObservation::vbs)) {
            SetResult(result, OwnerGateAction::Block, OwnerGateReason::VbsActive,
                      HvStatus::HardwareOwnerConflict,
                      owner, kOwnerGateFlagConflict, input.generation);
        } else if (IsPresent(input, &OwnerObservation::hvci)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::HvciActive,
                      HvStatus::HardwareOwnerConflict,
                      owner, kOwnerGateFlagConflict, input.generation);
        } else if (!HasNativeEvidence(input)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::UnknownOwner,
                      HvStatus::NestedUnavailable, owner, 0, input.generation);
        } else {
            SetResult(result, OwnerGateAction::AcquireNative,
                      OwnerGateReason::KnhvOwnerReady, HvStatus::Success,
                      owner, kOwnerGateFlagEvidenceComplete |
                                 kOwnerGateFlagExclusive,
                      input.generation);
        }
        return true;
    }

    if (IsExternalOwner(input)) {
        if (input.generation == 0) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::GenerationMissing,
                      HvStatus::IncompatibleProvider, owner, 0,
                      input.generation);
        } else {
            SetResult(result, OwnerGateAction::UseExternalProvider,
                      OwnerGateReason::ExternalOwnerActive,
                      HvStatus::IncompatibleProvider, owner,
                      kOwnerGateFlagFallback | kOwnerGateFlagConflict,
                      input.generation);
        }
        return true;
    }

    if (IsWhpOwner(input)) {
        if (input.generation == 0) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::GenerationMissing,
                      HvStatus::NestedUnavailable, owner, 0, input.generation);
        } else if (!IsAvailableOrActive(input) ||
                   !IsPresent(input, &OwnerObservation::whp_available)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::ProviderUnavailable,
                      HvStatus::NestedUnavailable, owner, 0, input.generation);
        } else {
            SetResult(result, OwnerGateAction::UseWhp,
                      OwnerGateReason::WhpFallback, HvStatus::Success, owner,
                      kOwnerGateFlagFallback, input.generation);
        }
        return true;
    }

    if (IsSyntheticOwner(input)) {
        if (input.generation == 0 || !IsAvailableOrActive(input)) {
            SetResult(result, OwnerGateAction::Block,
                      OwnerGateReason::ProviderStateInvalid,
                      HvStatus::NestedUnavailable, owner, 0, input.generation);
        } else {
            SetResult(result, OwnerGateAction::UseSynthetic,
                      OwnerGateReason::SyntheticFallback, HvStatus::Success,
                      owner, kOwnerGateFlagFallback, input.generation);
        }
        return true;
    }

    if (IsPresent(input, &OwnerObservation::vbs)) {
        SetResult(result, OwnerGateAction::Block, OwnerGateReason::VbsActive,
                  HvStatus::HardwareOwnerConflict,
                  owner, kOwnerGateFlagConflict, input.generation);
    } else if (IsPresent(input, &OwnerObservation::hvci)) {
        SetResult(result, OwnerGateAction::Block, OwnerGateReason::HvciActive,
                  HvStatus::HardwareOwnerConflict,
                  owner, kOwnerGateFlagConflict, input.generation);
    } else if (IsPresent(input, &OwnerObservation::windows_hypervisor)) {
        SetResult(result, OwnerGateAction::Block,
                  OwnerGateReason::WindowsHypervisorActive,
                  HvStatus::HardwareOwnerConflict,
                  owner, kOwnerGateFlagConflict, input.generation);
    } else if (IsPresent(input, &OwnerObservation::cpuid_hypervisor)) {
        SetResult(result, OwnerGateAction::Block,
                  OwnerGateReason::ExternalOwnerActive,
                  HvStatus::HardwareOwnerConflict,
                  owner, kOwnerGateFlagConflict, input.generation);
    } else if (!IsPresent(input, &OwnerObservation::provider_device)) {
        SetResult(result, OwnerGateAction::Block,
                  OwnerGateReason::ProviderUnavailable,
                  HvStatus::NestedUnavailable, owner, 0, input.generation);
    } else {
        SetResult(result, OwnerGateAction::Block, OwnerGateReason::UnknownOwner,
                  HvStatus::NestedUnavailable, owner, 0, input.generation);
    }
    return true;
}

bool IsOwnerGateResultValid(const OwnerGateResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(OwnerGateResult)) ||
        !IsActionValid(result->action) || !IsReasonValid(result->reason) ||
        !IsStatusValid(result->status) || !IsOwnerKindValid(result->owner) ||
        (result->flags & ~kOwnerGateKnownFlagMask) != 0 ||
        result->reserved != 0) {
        return false;
    }
    const auto action = static_cast<OwnerGateAction>(result->action);
    const auto owner = static_cast<HvOwnerKindV2>(result->owner);
    if (action == OwnerGateAction::AcquireNative) {
        return result->status == HvStatus::Success &&
               result->reason ==
                   static_cast<u32>(OwnerGateReason::KnhvOwnerReady) &&
               owner == HvOwnerKindV2::KnhvBootL0 && result->generation != 0 &&
               result->flags == (kOwnerGateFlagEvidenceComplete |
                                 kOwnerGateFlagExclusive);
    }
    if (action == OwnerGateAction::UseExternalProvider) {
        return result->status == HvStatus::IncompatibleProvider &&
               result->reason ==
                   static_cast<u32>(OwnerGateReason::ExternalOwnerActive) &&
               owner == HvOwnerKindV2::ExternalL0 && result->generation != 0 &&
               result->flags == (kOwnerGateFlagFallback |
                                 kOwnerGateFlagConflict);
    }
    if (action == OwnerGateAction::UseWhp) {
        return result->status == HvStatus::Success &&
               result->reason ==
                   static_cast<u32>(OwnerGateReason::WhpFallback) &&
               owner == HvOwnerKindV2::WhpManaged && result->generation != 0 &&
               result->flags == kOwnerGateFlagFallback;
    }
    if (action == OwnerGateAction::UseSynthetic) {
        return result->status == HvStatus::Success &&
               result->reason ==
                   static_cast<u32>(OwnerGateReason::SyntheticFallback) &&
               owner == HvOwnerKindV2::SyntheticLab && result->generation != 0 &&
               result->flags == kOwnerGateFlagFallback;
    }
    return IsBlockedResultConsistent(*result);
}

const char* OwnerGateActionText(OwnerGateAction action) {
    switch (action) {
        case OwnerGateAction::Block:
            return "block";
        case OwnerGateAction::AcquireNative:
            return "acquire-native";
        case OwnerGateAction::UseExternalProvider:
            return "use-external-provider";
        case OwnerGateAction::UseWhp:
            return "use-whp";
        case OwnerGateAction::UseSynthetic:
            return "use-synthetic";
        default:
            return "invalid";
    }
}

const char* OwnerGateReasonText(OwnerGateReason reason) {
    switch (reason) {
        case OwnerGateReason::None:
            return "none";
        case OwnerGateReason::InvalidObservation:
            return "invalid-observation";
        case OwnerGateReason::UnknownOwner:
            return "unknown-owner";
        case OwnerGateReason::ContradictoryEvidence:
            return "contradictory-evidence";
        case OwnerGateReason::WindowsHypervisorActive:
            return "windows-hypervisor-active";
        case OwnerGateReason::VbsActive:
            return "vbs-active";
        case OwnerGateReason::HvciActive:
            return "hvci-active";
        case OwnerGateReason::ExternalOwnerActive:
            return "external-owner-active";
        case OwnerGateReason::KnhvHandoffMissing:
            return "knhv-handoff-missing";
        case OwnerGateReason::KnhvOwnerReady:
            return "knhv-owner-ready";
        case OwnerGateReason::WhpFallback:
            return "whp-fallback";
        case OwnerGateReason::SyntheticFallback:
            return "synthetic-fallback";
        case OwnerGateReason::ProviderUnavailable:
            return "provider-unavailable";
        case OwnerGateReason::GenerationMissing:
            return "generation-missing";
        case OwnerGateReason::ProviderStateInvalid:
            return "provider-state-invalid";
        default:
            return "invalid";
    }
}

const char* OwnerKindText(HvOwnerKindV2 owner) {
    switch (owner) {
        case HvOwnerKindV2::Unknown:
            return "unknown";
        case HvOwnerKindV2::ExternalL0:
            return "external-l0";
        case HvOwnerKindV2::KnhvBootL0:
            return "knhv-boot-l0";
        case HvOwnerKindV2::WhpManaged:
            return "whp-managed";
        case HvOwnerKindV2::SyntheticLab:
            return "synthetic-lab";
        default:
            return "invalid";
    }
}

}  // namespace knhv
