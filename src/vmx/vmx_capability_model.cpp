#include "knhv_vmx_capability.h"

namespace knhv {
namespace {

constexpr u32 kFailureStatusMask =
    kVmxCapabilitySampleMsrReadFailed |
    kVmxCapabilitySampleOwnerConflict |
    kVmxCapabilitySampleFeatureControlBlocked;

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kVmxCapabilityContractVersion &&
           size >= required && size <= kVmxCapabilityMaxStructSize;
}

bool IsEncodingValid(u32 encoding) {
    return encoding == static_cast<u32>(VmxControlEncoding::Pair32) ||
           encoding == static_cast<u32>(VmxControlEncoding::AllowedOne64);
}

bool IsPair(const VmxControlCapability& capability) {
    return capability.encoding ==
           static_cast<u32>(VmxControlEncoding::Pair32);
}

bool IsAllowedOne64(const VmxControlCapability& capability) {
    return capability.encoding ==
           static_cast<u32>(VmxControlEncoding::AllowedOne64);
}

bool IsCollected(const VmxCapabilitySample& sample) {
    return (sample.status & kVmxCapabilitySampleCollected) != 0 &&
           (sample.status & kFailureStatusMask) == 0;
}

bool IsFailureStatus(u32 status) {
    return (status & kVmxCapabilitySampleCollected) == 0 &&
           (status & kFailureStatusMask) != 0;
}

bool IsControlZero(const VmxControlCapability& capability) {
    return capability.size == 0 && capability.version == 0 &&
           capability.encoding == 0 && capability.reserved == 0 &&
           capability.mandatory_one == 0 && capability.allowed_one == 0;
}

bool IsPayloadZero(const VmxCapabilitySample& sample) {
    return sample.generation == 0 && sample.vmx_basic == 0 &&
           sample.feature_control == 0 && sample.ept_vpid_cap == 0 &&
           IsControlZero(sample.pin_controls) &&
           IsControlZero(sample.primary_controls) &&
           IsControlZero(sample.secondary_controls) &&
           IsControlZero(sample.tertiary_controls) &&
           IsControlZero(sample.exit_controls) &&
           IsControlZero(sample.entry_controls) && sample.cr0_fixed0 == 0 &&
           sample.cr0_fixed1 == 0 && sample.cr4_fixed0 == 0 &&
           sample.cr4_fixed1 == 0 && sample.reserved[0] == 0 &&
           sample.reserved[1] == 0;
}

bool IsControlBitAllowed(const VmxControlCapability& capability, u64 bit) {
    return IsVmxControlCapabilityValid(&capability) &&
           (capability.allowed_one & bit) != 0;
}

bool SameControl(const VmxControlCapability& left,
                 const VmxControlCapability& right) {
    return left.encoding == right.encoding &&
           left.mandatory_one == right.mandatory_one &&
           left.allowed_one == right.allowed_one;
}

bool SameIdentity(const VmxCapabilitySample& left,
                  const VmxCapabilitySample& right) {
    return left.generation == right.generation &&
           left.vmx_basic == right.vmx_basic &&
           left.feature_control == right.feature_control &&
           left.ept_vpid_cap == right.ept_vpid_cap &&
           SameControl(left.pin_controls, right.pin_controls) &&
           SameControl(left.primary_controls, right.primary_controls) &&
           SameControl(left.secondary_controls, right.secondary_controls) &&
           SameControl(left.tertiary_controls, right.tertiary_controls) &&
           SameControl(left.exit_controls, right.exit_controls) &&
           SameControl(left.entry_controls, right.entry_controls) &&
           left.cr0_fixed0 == right.cr0_fixed0 &&
           left.cr0_fixed1 == right.cr0_fixed1 &&
           left.cr4_fixed0 == right.cr4_fixed0 &&
           left.cr4_fixed1 == right.cr4_fixed1;
}

void InitializeMatrix(VmxCapabilityMatrix* matrix, u32 expected_count,
                      u32 sample_count) {
    *matrix = {};
    matrix->size = sizeof(*matrix);
    matrix->version = kVmxCapabilityContractVersion;
    matrix->state = static_cast<u32>(VmxCapabilityMatrixState::Invalid);
    matrix->expected_count = expected_count;
    matrix->sample_count = sample_count;
}

}  // namespace

bool IsVmxControlCapabilityValid(const VmxControlCapability* capability) {
    if (capability == nullptr ||
        !IsVersionedSizeValid(capability->version, capability->size,
                              sizeof(VmxControlCapability)) ||
        !IsEncodingValid(capability->encoding) || capability->reserved != 0) {
        return false;
    }
    if (IsPair(*capability)) {
        return (capability->mandatory_one >> 32) == 0 &&
               (capability->allowed_one >> 32) == 0 &&
               (capability->mandatory_one & ~capability->allowed_one) == 0;
    }
    return IsAllowedOne64(*capability) && capability->mandatory_one == 0;
}

bool IsVmxControlValueAllowed(const VmxControlCapability* capability,
                              u64 value) {
    if (!IsVmxControlCapabilityValid(capability)) return false;
    if (IsPair(*capability) && (value >> 32) != 0) return false;
    return (value & ~capability->allowed_one) == 0 &&
           (value & capability->mandatory_one) == capability->mandatory_one;
}

bool NormalizeVmxControlValue(const VmxControlCapability* capability,
                              u64 requested, u64* normalized) {
    if (normalized == nullptr) return false;
    *normalized = 0;
    if (!IsVmxControlCapabilityValid(capability) ||
        (IsPair(*capability) && (requested >> 32) != 0) ||
        (requested & ~capability->allowed_one) != 0) {
        return false;
    }
    *normalized = (requested | capability->mandatory_one) &
                  capability->allowed_one;
    return IsVmxControlValueAllowed(capability, *normalized);
}

bool IsVmxCapabilitySampleValid(const VmxCapabilitySample* sample) {
    if (sample == nullptr ||
        !IsVersionedSizeValid(sample->version, sample->size,
                              sizeof(VmxCapabilitySample)) ||
        sample->logical_index >= kVmxCapabilityMaxProcessors ||
        sample->processor_group > 0xFFFFU || sample->processor_number >= 64U ||
        sample->reserved0 != 0 || sample->reserved1 != 0 ||
        (sample->status & ~kVmxCapabilityKnownSampleStatusMask) != 0) {
        return false;
    }

    const bool collected = IsCollected(*sample);
    const bool failed = IsFailureStatus(sample->status);
    if (collected == failed ||
        ((sample->status & kVmxCapabilitySampleCollected) != 0 &&
         (sample->status & kFailureStatusMask) != 0)) {
        return false;
    }
    if (failed) return IsPayloadZero(*sample);
    if (sample->generation == 0 ||
        (sample->vmx_basic & kVmxBasicRevisionMask) == 0 ||
        !IsVmxControlCapabilityValid(&sample->pin_controls) ||
        !IsVmxControlCapabilityValid(&sample->primary_controls) ||
        !IsVmxControlCapabilityValid(&sample->secondary_controls) ||
        !IsVmxControlCapabilityValid(&sample->tertiary_controls) ||
        !IsVmxControlCapabilityValid(&sample->exit_controls) ||
        !IsVmxControlCapabilityValid(&sample->entry_controls) ||
        (sample->cr0_fixed0 & ~sample->cr0_fixed1) != 0 ||
        (sample->cr4_fixed0 & ~sample->cr4_fixed1) != 0 ||
        sample->reserved[0] != 0 || sample->reserved[1] != 0) {
        return false;
    }
    if (!IsPair(sample->pin_controls) ||
        !IsPair(sample->primary_controls) ||
        !IsPair(sample->secondary_controls) ||
        !IsAllowedOne64(sample->tertiary_controls) ||
        !IsPair(sample->exit_controls) ||
        !IsPair(sample->entry_controls)) {
        return false;
    }
    return true;
}

bool IsVmxCapabilitySampleUsable(const VmxCapabilitySample* sample) {
    return IsVmxCapabilitySampleValid(sample) && sample != nullptr &&
           IsCollected(*sample);
}

u64 GetVmxCapabilityFeatureFlags(const VmxCapabilitySample* sample) {
    if (!IsVmxCapabilitySampleUsable(sample)) return 0;

    u64 flags = kVmxFeatureVmx;
    if ((sample->vmx_basic & kVmxBasicTrueControls) != 0) {
        flags |= kVmxFeatureTrueControls;
    }
    if ((sample->feature_control &
         (kVmxFeatureControlLock | kVmxFeatureControlVmxonOutsideSmx)) ==
        (kVmxFeatureControlLock | kVmxFeatureControlVmxonOutsideSmx)) {
        flags |= kVmxFeatureControlReady;
    }

    const bool secondary =
        IsControlBitAllowed(sample->primary_controls,
                            kVmxPrimaryActivateSecondary);
    if (!secondary) return flags;
    flags |= kVmxFeatureSecondaryControls;

    const bool tertiary =
        IsControlBitAllowed(sample->primary_controls,
                            kVmxPrimaryActivateTertiary) &&
        sample->tertiary_controls.allowed_one != 0;
    if (tertiary) flags |= kVmxFeatureTertiaryControls;

    const bool ept =
        IsControlBitAllowed(sample->secondary_controls,
                            kVmxSecondaryEnableEpt) &&
        (sample->ept_vpid_cap & kVmxEptVpidCapBasicEpt) ==
            kVmxEptVpidCapBasicEpt;
    if (ept) flags |= kVmxFeatureEpt;

    const bool vpid =
        IsControlBitAllowed(sample->secondary_controls,
                            kVmxSecondaryEnableVpid) &&
        (sample->ept_vpid_cap & kVmxEptVpidCapInvvpid) != 0;
    if (vpid) flags |= kVmxFeatureVpid;

    if (ept && (sample->ept_vpid_cap & kVmxEptVpidCapFullInvept) ==
                   kVmxEptVpidCapFullInvept) {
        flags |= kVmxFeatureInvept;
    }
    if (vpid && (sample->ept_vpid_cap & kVmxEptVpidCapFullInvvpid) ==
                    kVmxEptVpidCapFullInvvpid) {
        flags |= kVmxFeatureInvvpid;
    }
    if (IsControlBitAllowed(sample->secondary_controls,
                            kVmxSecondaryEnableTscScaling)) {
        flags |= kVmxFeatureTscScaling;
    }
    return flags;
}

bool NormalizeVmxControlSet(const VmxCapabilitySample* sample,
                            const VmxControlSet* requested,
                            VmxControlSet* normalized) {
    if (normalized == nullptr) return false;
    *normalized = {};
    if (!IsVmxCapabilitySampleUsable(sample) || requested == nullptr ||
        !IsVersionedSizeValid(requested->version, requested->size,
                              sizeof(VmxControlSet))) {
        return false;
    }
    const u64 required_feature_control =
        kVmxFeatureControlLock | kVmxFeatureControlVmxonOutsideSmx;
    if ((sample->feature_control & required_feature_control) !=
        required_feature_control) {
        return false;
    }

    normalized->size = sizeof(*normalized);
    normalized->version = kVmxCapabilityContractVersion;
    u64 value = 0;
    if (!NormalizeVmxControlValue(&sample->pin_controls,
                                  requested->pin_controls, &value)) {
        *normalized = {};
        return false;
    }
    normalized->pin_controls = static_cast<u32>(value);
    if (!NormalizeVmxControlValue(&sample->primary_controls,
                                  requested->primary_controls, &value)) {
        *normalized = {};
        return false;
    }
    normalized->primary_controls = static_cast<u32>(value);
    if (!NormalizeVmxControlValue(&sample->secondary_controls,
                                  requested->secondary_controls, &value)) {
        *normalized = {};
        return false;
    }
    normalized->secondary_controls = static_cast<u32>(value);
    if (!NormalizeVmxControlValue(&sample->exit_controls,
                                  requested->exit_controls, &value)) {
        *normalized = {};
        return false;
    }
    normalized->exit_controls = static_cast<u32>(value);
    if (!NormalizeVmxControlValue(&sample->entry_controls,
                                  requested->entry_controls, &value)) {
        *normalized = {};
        return false;
    }
    normalized->entry_controls = static_cast<u32>(value);
    if (!NormalizeVmxControlValue(&sample->tertiary_controls,
                                  requested->tertiary_controls, &value)) {
        *normalized = {};
        return false;
    }
    normalized->tertiary_controls = value;

    if (normalized->secondary_controls != 0 &&
        (normalized->primary_controls & kVmxPrimaryActivateSecondary) == 0) {
        *normalized = {};
        return false;
    }
    if (normalized->tertiary_controls != 0 &&
        (normalized->primary_controls & kVmxPrimaryActivateTertiary) == 0) {
        *normalized = {};
        return false;
    }
    if ((normalized->secondary_controls & kVmxSecondaryEnableEpt) != 0 &&
        (sample->ept_vpid_cap & kVmxEptVpidCapBasicEpt) !=
            kVmxEptVpidCapBasicEpt) {
        *normalized = {};
        return false;
    }
    if ((normalized->secondary_controls & kVmxSecondaryEnableVpid) != 0 &&
        (sample->ept_vpid_cap & kVmxEptVpidCapInvvpid) == 0) {
        *normalized = {};
        return false;
    }
    return true;
}

bool BuildVmxCapabilityMatrix(const VmxCapabilitySample* samples,
                              u32 sample_count, u32 expected_count,
                              VmxCapabilityMatrix* matrix) {
    if (matrix == nullptr || sample_count > kVmxCapabilityMaxProcessors ||
        expected_count > kVmxCapabilityMaxProcessors ||
        (sample_count != 0 && samples == nullptr)) {
        if (matrix != nullptr) InitializeMatrix(matrix, expected_count,
                                                 sample_count);
        return false;
    }

    InitializeMatrix(matrix, expected_count, sample_count);
    if (sample_count == 0) {
        matrix->state = expected_count == 0
                            ? static_cast<u32>(VmxCapabilityMatrixState::Empty)
                            : static_cast<u32>(VmxCapabilityMatrixState::Incomplete);
        if (expected_count == 0) matrix->flags |= kVmxMatrixSamplesComplete;
        return true;
    }

    const VmxCapabilitySample* first_valid = nullptr;
    bool identity_uniform = true;
    for (u32 index = 0; index < sample_count; ++index) {
        const VmxCapabilitySample& sample = samples[index];
        if (!IsVmxCapabilitySampleValid(&sample)) {
            matrix->state = static_cast<u32>(VmxCapabilityMatrixState::Invalid);
            return false;
        }
        for (u32 prior = 0; prior < index; ++prior) {
            const VmxCapabilitySample& previous = samples[prior];
            if (sample.logical_index == previous.logical_index ||
                (sample.processor_group == previous.processor_group &&
                 sample.processor_number == previous.processor_number)) {
                matrix->state = static_cast<u32>(VmxCapabilityMatrixState::Invalid);
                return false;
            }
        }
        if (!IsVmxCapabilitySampleUsable(&sample)) {
            ++matrix->invalid_count;
            continue;
        }

        const u64 features = GetVmxCapabilityFeatureFlags(&sample);
        if (first_valid == nullptr) {
            first_valid = &sample;
            matrix->feature_intersection = features;
            matrix->feature_union = features;
            matrix->ept_vpid_intersection = sample.ept_vpid_cap;
            matrix->ept_vpid_union = sample.ept_vpid_cap;
            matrix->generation = sample.generation;
            continue;
        }
        matrix->feature_intersection &= features;
        matrix->feature_union |= features;
        matrix->ept_vpid_intersection &= sample.ept_vpid_cap;
        matrix->ept_vpid_union |= sample.ept_vpid_cap;
        if (!SameIdentity(*first_valid, sample)) identity_uniform = false;
    }

    matrix->valid_count = sample_count - matrix->invalid_count;
    matrix->inconsistent_features = matrix->feature_union ^
                                     matrix->feature_intersection;
    if (matrix->valid_count != 0 &&
        (matrix->feature_intersection & kVmxFeatureVmx) != 0) {
        matrix->flags |= kVmxMatrixAllVmx;
    }
    if (identity_uniform && matrix->valid_count != 0) {
        matrix->flags |= kVmxMatrixIdentityUniform;
    }
    if (matrix->invalid_count != 0) {
        matrix->flags |= kVmxMatrixHasInvalidSamples;
    }
    if (matrix->sample_count == matrix->expected_count &&
        matrix->valid_count == matrix->expected_count) {
        matrix->flags |= kVmxMatrixSamplesComplete;
    }

    if (sample_count != expected_count || matrix->invalid_count != 0 ||
        expected_count == 0) {
        matrix->state = static_cast<u32>(VmxCapabilityMatrixState::Incomplete);
    } else if (!identity_uniform || matrix->inconsistent_features != 0 ||
               matrix->ept_vpid_intersection != matrix->ept_vpid_union) {
        matrix->state = static_cast<u32>(VmxCapabilityMatrixState::CompleteMixed);
    } else {
        matrix->state = static_cast<u32>(VmxCapabilityMatrixState::CompleteUniform);
    }
    return true;
}

bool IsVmxCapabilityMatrixValid(const VmxCapabilityMatrix* matrix) {
    if (matrix == nullptr ||
        !IsVersionedSizeValid(matrix->version, matrix->size,
                              sizeof(VmxCapabilityMatrix)) ||
        matrix->state >
            static_cast<u32>(VmxCapabilityMatrixState::Invalid) ||
        (matrix->flags & ~kVmxMatrixKnownFlagMask) != 0 ||
        matrix->expected_count > kVmxCapabilityMaxProcessors ||
        matrix->sample_count > kVmxCapabilityMaxProcessors ||
        matrix->valid_count > matrix->sample_count ||
        matrix->invalid_count > matrix->sample_count ||
        matrix->valid_count + matrix->invalid_count != matrix->sample_count ||
        (matrix->feature_intersection & ~matrix->feature_union) != 0 ||
        (matrix->feature_intersection & ~kVmxCapabilityKnownFeatureMask) != 0 ||
        (matrix->feature_union & ~kVmxCapabilityKnownFeatureMask) != 0 ||
        matrix->inconsistent_features !=
            (matrix->feature_union ^ matrix->feature_intersection) ||
        (matrix->ept_vpid_intersection & ~matrix->ept_vpid_union) != 0 ||
        matrix->reserved[0] != 0 || matrix->reserved[1] != 0 ||
        matrix->reserved[2] != 0 || matrix->reserved[3] != 0) {
        return false;
    }

    const bool all_vmx = matrix->valid_count != 0 &&
                         (matrix->feature_intersection & kVmxFeatureVmx) != 0;
    const bool samples_complete =
        matrix->expected_count == matrix->sample_count &&
        matrix->valid_count == matrix->expected_count;
    const bool has_invalid = matrix->invalid_count != 0;
    if (((matrix->flags & kVmxMatrixAllVmx) != 0) != all_vmx ||
        ((matrix->flags & kVmxMatrixSamplesComplete) != 0) !=
            samples_complete ||
        ((matrix->flags & kVmxMatrixHasInvalidSamples) != 0) != has_invalid ||
        (matrix->valid_count == 0 &&
         (matrix->flags & kVmxMatrixIdentityUniform) != 0)) {
        return false;
    }

    const auto state = static_cast<VmxCapabilityMatrixState>(matrix->state);
    if (state == VmxCapabilityMatrixState::Empty) {
        return matrix->expected_count == 0 && matrix->sample_count == 0 &&
               matrix->valid_count == 0 && matrix->invalid_count == 0 &&
               matrix->generation == 0;
    }
    if ((matrix->valid_count == 0 && matrix->generation != 0) ||
        (matrix->valid_count != 0 && matrix->generation == 0)) {
        return false;
    }
    const bool complete_nonempty =
        matrix->expected_count == matrix->sample_count &&
        matrix->expected_count != 0 && matrix->invalid_count == 0 &&
        (matrix->flags & kVmxMatrixSamplesComplete) != 0;
    const bool uniform_candidate =
        (matrix->flags & kVmxMatrixIdentityUniform) != 0 &&
        matrix->inconsistent_features == 0 &&
        matrix->ept_vpid_intersection == matrix->ept_vpid_union;
    if (state == VmxCapabilityMatrixState::CompleteUniform) {
        return complete_nonempty && uniform_candidate;
    }
    if (state == VmxCapabilityMatrixState::CompleteMixed) {
        return complete_nonempty && !uniform_candidate;
    }
    if (state == VmxCapabilityMatrixState::Invalid) return false;
    if (state == VmxCapabilityMatrixState::Incomplete &&
        complete_nonempty) {
        return false;
    }
    return true;
}

bool IsVmxCapabilityMatrixUniform(const VmxCapabilityMatrix* matrix,
                                  u64 required_features,
                                  u64 required_ept_vpid_caps) {
    constexpr u64 kKnownEptVpidCaps =
        kVmxEptVpidCapBasicEpt | kVmxEptVpidCapFullInvept |
        kVmxEptVpidCapFullInvvpid;
    return IsVmxCapabilityMatrixValid(matrix) &&
           matrix->state ==
               static_cast<u32>(VmxCapabilityMatrixState::CompleteUniform) &&
           (required_features & ~kVmxCapabilityKnownFeatureMask) == 0 &&
           (required_ept_vpid_caps & ~kKnownEptVpidCaps) == 0 &&
           (matrix->feature_intersection & required_features) ==
               required_features &&
           (matrix->ept_vpid_intersection & required_ept_vpid_caps) ==
               required_ept_vpid_caps;
}

}  // namespace knhv
