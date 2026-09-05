#include "knhv_provider.h"

namespace knhv {
namespace {

constexpr u64 kV2HardwareFeatureMask =
    kCapVmx | kCapEpt | kCapVpid | kCapIommu | kCapVirtualApic |
    kCapTscContract;
constexpr u64 kV2ProviderFeatureMask =
    kCapNestedVmx | kCapEnlightenedVmcs | kCapVirtualTlbFlush |
    kCapWhpPartition | kCapBootL0;

bool IsOwnerKindValid(u32 value) {
    switch (static_cast<HvOwnerKindV2>(value)) {
        case HvOwnerKindV2::Unknown:
        case HvOwnerKindV2::ExternalL0:
        case HvOwnerKindV2::KnhvBootL0:
        case HvOwnerKindV2::WhpManaged:
        case HvOwnerKindV2::SyntheticLab:
            return true;
        default:
            return false;
    }
}

bool IsProviderStateValid(u32 value) {
    switch (static_cast<HvProviderStateV2>(value)) {
        case HvProviderStateV2::Unknown:
        case HvProviderStateV2::Available:
        case HvProviderStateV2::Active:
        case HvProviderStateV2::Conflict:
        case HvProviderStateV2::Blocked:
        case HvProviderStateV2::Quarantined:
            return true;
        default:
            return false;
    }
}

bool IsLeaseModeValid(u32 value) {
    switch (static_cast<HvLeaseModeV2>(value)) {
        case HvLeaseModeV2::None:
        case HvLeaseModeV2::HardwareL0:
        case HvLeaseModeV2::WhpManaged:
        case HvLeaseModeV2::SyntheticLab:
            return true;
        default:
            return false;
    }
}

bool IsRequestModeValid(u32 value) {
    return IsLeaseModeValid(value) && value !=
        static_cast<u32>(HvLeaseModeV2::None);
}

bool RequiredFeaturesKnown(const HvProviderRequestV2* request) {
    return request != nullptr &&
           (request->required_hardware_features & ~kV2HardwareFeatureMask) == 0 &&
           (request->required_provider_features & ~kV2ProviderFeatureMask) == 0 &&
           (request->required_policy_features & ~kKnownPolicyFeatureMask) == 0;
}

bool RequestV2Valid(const HvProviderRequestV2* request) {
    return request != nullptr &&
           IsAbiV2BufferValid(request->version, request->size,
                              sizeof(HvProviderRequestV2)) &&
           request->session.reserved == 0 &&
           (request->flags & ~kKnownV2RequestFlagMask) == 0 &&
           IsRequestModeValid(request->mode) && RequiredFeaturesKnown(request);
}

u64 CapabilityGeneration(const HvCapabilitySnapshot* capabilities) {
    if (capabilities == nullptr) return 0;
    if (capabilities->owner_generation != 0) {
        return capabilities->owner_generation;
    }
    return capabilities->boot_generation;
}

void SetLease(HvOwnerLeaseV2* lease, u64 owner_id, u64 generation,
              HvLeaseModeV2 mode, u32 flags) {
    if (lease == nullptr) return;
    *lease = {};
    lease->size = sizeof(*lease);
    lease->version = kAbiV2Version;
    lease->owner_id = owner_id;
    lease->generation = generation;
    lease->mode = static_cast<u32>(mode);
    lease->flags = flags;
}

bool HasRequiredFeatures(const HvProviderRequestV2* request,
                         const HvCapabilitySnapshotV2* capabilities) {
    return (request->required_hardware_features &
            ~capabilities->hardware_features) == 0 &&
           (request->required_provider_features &
            ~capabilities->provider_features) == 0 &&
           (request->required_policy_features &
            ~capabilities->policy_features) == 0;
}

}  // namespace

HvCapabilitySnapshotV2 MakeCapabilitySnapshotV2(
    const HvCapabilitySnapshot* capabilities) {
    HvCapabilitySnapshotV2 snapshot = {};
    snapshot.size = sizeof(snapshot);
    snapshot.version = kAbiV2Version;
    if (capabilities == nullptr ||
        !IsVersionedBufferValid(capabilities->version, capabilities->size,
                                sizeof(HvCapabilitySnapshot))) {
        snapshot.state = static_cast<u32>(HvProviderStateV2::Blocked);
        return snapshot;
    }

    snapshot.hardware_features = capabilities->feature_bits &
                                 kV2HardwareFeatureMask;
    snapshot.provider_features = capabilities->feature_bits &
                                 kV2ProviderFeatureMask;
    snapshot.generation = CapabilityGeneration(capabilities);
    const u32 flags = capabilities->status_flags;
    const u32 owner_flags =
        ((flags & kFlagSyntheticSnapshot) != 0 ? 1U : 0U) +
        ((flags & kFlagKnhvBootL0Active) != 0 ? 1U : 0U) +
        ((flags & kFlagOuterL0Active) != 0 ? 1U : 0U) +
        ((flags & kFlagWhpPartition) != 0 ? 1U : 0U);
    if (owner_flags > 1U) {
        snapshot.owner_kind = static_cast<u32>(HvOwnerKindV2::Unknown);
        snapshot.state = static_cast<u32>(HvProviderStateV2::Conflict);
        snapshot.policy_features = kPolicyNoPhysicalDma;
    } else if ((flags & kFlagSyntheticSnapshot) != 0) {
        snapshot.owner_kind = static_cast<u32>(HvOwnerKindV2::SyntheticLab);
        snapshot.state = static_cast<u32>(HvProviderStateV2::Available);
        snapshot.policy_features = kPolicySyntheticOnly |
                                   kPolicyNoPhysicalDma;
    } else if ((flags & kFlagKnhvBootL0Active) != 0) {
        snapshot.owner_kind = static_cast<u32>(HvOwnerKindV2::KnhvBootL0);
        snapshot.state = (flags & kFlagBootHandoffVerified) != 0
                             ? static_cast<u32>(HvProviderStateV2::Active)
                             : static_cast<u32>(HvProviderStateV2::Blocked);
        snapshot.policy_features = kPolicyExclusiveOwner |
                                   kPolicyWindowsHandoff;
    } else if ((flags & kFlagOuterL0Active) != 0) {
        snapshot.owner_kind = static_cast<u32>(HvOwnerKindV2::ExternalL0);
        snapshot.state = static_cast<u32>(HvProviderStateV2::Conflict);
        snapshot.policy_features = kPolicyNoPhysicalDma;
    } else if ((flags & kFlagWhpPartition) != 0) {
        snapshot.owner_kind = static_cast<u32>(HvOwnerKindV2::WhpManaged);
        snapshot.state = static_cast<u32>(HvProviderStateV2::Available);
        snapshot.policy_features = kPolicyNoPhysicalDma;
    } else {
        snapshot.owner_kind = static_cast<u32>(HvOwnerKindV2::Unknown);
        snapshot.state = static_cast<u32>(HvProviderStateV2::Blocked);
    }
    return snapshot;
}

bool IsCapabilitySnapshotV2Valid(
    const HvCapabilitySnapshotV2* capabilities) {
    if (capabilities == nullptr ||
        !IsAbiV2BufferValid(capabilities->version, capabilities->size,
                            sizeof(HvCapabilitySnapshotV2)) ||
        (capabilities->hardware_features & ~kV2HardwareFeatureMask) != 0 ||
        (capabilities->provider_features & ~kV2ProviderFeatureMask) != 0 ||
        (capabilities->policy_features & ~kKnownPolicyFeatureMask) != 0 ||
        !IsOwnerKindValid(capabilities->owner_kind) ||
        !IsProviderStateValid(capabilities->state)) {
        return false;
    }
    const auto owner = static_cast<HvOwnerKindV2>(capabilities->owner_kind);
    const auto state = static_cast<HvProviderStateV2>(capabilities->state);
    if (state == HvProviderStateV2::Active &&
        (owner == HvOwnerKindV2::Unknown || capabilities->generation == 0)) {
        return false;
    }
    if (owner == HvOwnerKindV2::SyntheticLab &&
        ((capabilities->policy_features & kPolicySyntheticOnly) == 0 ||
         (capabilities->provider_features & kCapNestedVmx) == 0)) {
        return false;
    }
    if (owner == HvOwnerKindV2::KnhvBootL0 &&
        ((capabilities->policy_features & kPolicyExclusiveOwner) == 0 ||
         (capabilities->provider_features & kCapBootL0) == 0 ||
         (capabilities->hardware_features & kCapVmx) == 0)) {
        return false;
    }
    if (owner == HvOwnerKindV2::WhpManaged &&
        (capabilities->provider_features & kCapWhpPartition) == 0) {
        return false;
    }
    return true;
}

bool IsOwnerLeaseV2Valid(const HvOwnerLeaseV2* lease) {
    if (lease == nullptr ||
        !IsAbiV2BufferValid(lease->version, lease->size,
                            sizeof(HvOwnerLeaseV2)) ||
        (lease->flags & ~kKnownV2LeaseFlagMask) != 0 ||
        !IsLeaseModeValid(lease->mode)) {
        return false;
    }
    if (lease->mode == static_cast<u32>(HvLeaseModeV2::None)) {
        return lease->owner_id == 0 && lease->generation == 0 &&
               lease->flags == 0;
    }
    if (lease->owner_id == 0 || lease->generation == 0) return false;
    if (lease->mode == static_cast<u32>(HvLeaseModeV2::HardwareL0) &&
        (lease->flags & kLeaseFlagExclusive) == 0) {
        return false;
    }
    if (lease->mode == static_cast<u32>(HvLeaseModeV2::SyntheticLab) &&
        (lease->flags & kLeaseFlagSynthetic) == 0) {
        return false;
    }
    if (lease->mode != static_cast<u32>(HvLeaseModeV2::SyntheticLab) &&
        (lease->flags & kLeaseFlagSynthetic) != 0) {
        return false;
    }
    if (lease->mode != static_cast<u32>(HvLeaseModeV2::HardwareL0) &&
        (lease->flags & kLeaseFlagExclusive) != 0) {
        return false;
    }
    return true;
}

bool LeaseMatchesCapabilityV2(const HvOwnerLeaseV2* lease,
                              const HvCapabilitySnapshotV2* capabilities) {
    if (!IsOwnerLeaseV2Valid(lease) ||
        !IsCapabilitySnapshotV2Valid(capabilities) ||
        lease->generation != capabilities->generation) {
        return false;
    }
    switch (static_cast<HvLeaseModeV2>(lease->mode)) {
        case HvLeaseModeV2::HardwareL0:
            return capabilities->owner_kind ==
                       static_cast<u32>(HvOwnerKindV2::KnhvBootL0) &&
                   capabilities->state ==
                       static_cast<u32>(HvProviderStateV2::Active) &&
                   (capabilities->policy_features &
                    kPolicyExclusiveOwner) != 0;
        case HvLeaseModeV2::WhpManaged:
            return capabilities->owner_kind ==
                       static_cast<u32>(HvOwnerKindV2::WhpManaged) &&
                   capabilities->state !=
                       static_cast<u32>(HvProviderStateV2::Conflict) &&
                   capabilities->state !=
                       static_cast<u32>(HvProviderStateV2::Blocked);
        case HvLeaseModeV2::SyntheticLab:
            return capabilities->owner_kind ==
                       static_cast<u32>(HvOwnerKindV2::SyntheticLab) &&
                   (capabilities->policy_features & kPolicySyntheticOnly) != 0;
        default:
            return false;
    }
}

HvStatus SelectProviderV2(const HvProviderRequestV2* request,
                          const HvCapabilitySnapshotV2* capabilities,
                          HvProviderResponseV2* response) {
    if (response == nullptr) return HvStatus::InvalidParameter;
    *response = {};
    response->size = sizeof(*response);
    response->version = kAbiV2Version;
    if (request != nullptr) response->request_id = request->request_id;
    if (!RequestV2Valid(request) ||
        !IsCapabilitySnapshotV2Valid(capabilities)) {
        response->status = HvStatus::InvalidParameter;
        return response->status;
    }
    response->capabilities = *capabilities;
    if (!HasRequiredFeatures(request, capabilities)) {
        response->status = HvStatus::CapabilityMismatch;
        return response->status;
    }
    if (request->session.client_id == 0 || request->session.generation == 0) {
        response->status = HvStatus::InvalidParameter;
        return response->status;
    }

    const auto mode = static_cast<HvLeaseModeV2>(request->mode);
    const auto owner = static_cast<HvOwnerKindV2>(capabilities->owner_kind);
    const auto state = static_cast<HvProviderStateV2>(capabilities->state);
    const u32 read_only = (request->flags & kRequestFlagReadOnly) != 0
                              ? kLeaseFlagReadOnly
                              : 0U;
    switch (mode) {
        case HvLeaseModeV2::HardwareL0:
            if (owner == HvOwnerKindV2::ExternalL0 ||
                state == HvProviderStateV2::Conflict) {
                response->status = HvStatus::HardwareOwnerConflict;
                return response->status;
            }
            if (owner != HvOwnerKindV2::KnhvBootL0 ||
                state != HvProviderStateV2::Active) {
                response->status = HvStatus::NestedUnavailable;
                return response->status;
            }
            if ((capabilities->hardware_features & kCapVmx) == 0) {
                response->status = HvStatus::HardwareUnsupported;
                return response->status;
            }
            if ((request->flags & kRequestFlagRequireExclusive) != 0 &&
                (capabilities->policy_features & kPolicyExclusiveOwner) == 0) {
                response->status = HvStatus::HardwareOwnerConflict;
                return response->status;
            }
            if ((capabilities->policy_features & kPolicyWindowsHandoff) == 0) {
                response->status = HvStatus::BootHandoffFailed;
                return response->status;
            }
            response->provider = HvProviderKind::BootL0Interposer;
            SetLease(&response->lease, request->session.client_id,
                     capabilities->generation, mode,
                     kLeaseFlagExclusive | read_only);
            response->status = HvStatus::Success;
            return response->status;

        case HvLeaseModeV2::WhpManaged:
            if ((capabilities->provider_features & kCapWhpPartition) == 0 ||
                owner != HvOwnerKindV2::WhpManaged ||
                (state != HvProviderStateV2::Available &&
                 state != HvProviderStateV2::Active)) {
                response->status = HvStatus::NestedUnavailable;
                return response->status;
            }
            response->provider = HvProviderKind::WhpClient;
            SetLease(&response->lease, request->session.client_id,
                     capabilities->generation, mode, read_only);
            response->status = HvStatus::Success;
            return response->status;

        case HvLeaseModeV2::SyntheticLab:
            if (owner != HvOwnerKindV2::SyntheticLab ||
                (capabilities->provider_features & kCapNestedVmx) == 0 ||
                (capabilities->policy_features & kPolicySyntheticOnly) == 0 ||
                (state != HvProviderStateV2::Available &&
                 state != HvProviderStateV2::Active)) {
                response->status = HvStatus::NestedUnavailable;
                return response->status;
            }
            response->provider = HvProviderKind::CooperativeL1;
            SetLease(&response->lease, request->session.client_id,
                     capabilities->generation, mode,
                     kLeaseFlagSynthetic | read_only);
            response->status = HvStatus::Success;
            return response->status;

        default:
            response->status = HvStatus::UnsupportedMode;
            return response->status;
    }
}

}  // namespace knhv
