#include "knhv_provider.h"

namespace knhv {
namespace {

bool RequestIsValid(const HvProviderRequest* request) {
    if (request == nullptr ||
        !IsVersionedBufferValid(request->version, request->size,
                                sizeof(HvProviderRequest))) {
        return false;
    }
    return request->reserved == 0;
}

bool SnapshotIsValid(const HvCapabilitySnapshot* capabilities) {
    if (capabilities == nullptr ||
        !IsVersionedBufferValid(capabilities->version, capabilities->size,
                                sizeof(HvCapabilitySnapshot))) {
        return false;
    }
    constexpr u32 kKnownStatusFlagMask =
        kFlagOuterL0Active | kFlagNativeVmxReady |
        kFlagBootHandoffVerified | kFlagKnhvBootL0Active | kFlagNestedVmx |
        kFlagWhpPartition | kFlagSyntheticSnapshot;
    if (capabilities->hypervisor_vendor_length > 12U ||
        (capabilities->feature_bits & ~kKnownCapabilityMask) != 0 ||
        (capabilities->status_flags & ~kKnownStatusFlagMask) != 0 ||
        capabilities->max_physical_address_bits == 0 ||
        capabilities->max_physical_address_bits > 52U) {
        return false;
    }
    const u32 flags = capabilities->status_flags;
    const u64 features = capabilities->feature_bits;
    if ((flags & kFlagOuterL0Active) != 0 &&
        (flags & kFlagKnhvBootL0Active) != 0) {
        return false;
    }
    if ((flags & (kFlagBootHandoffVerified | kFlagKnhvBootL0Active)) != 0 &&
        (features & kCapBootL0) == 0) {
        return false;
    }
    if ((flags & (kFlagNestedVmx | kFlagSyntheticSnapshot)) != 0 &&
        (features & kCapNestedVmx) == 0) {
        return false;
    }
    if ((flags & kFlagWhpPartition) != 0 &&
        (features & kCapWhpPartition) == 0) {
        return false;
    }
    if ((flags & kFlagNativeVmxReady) != 0 &&
        (features & kCapVmx) == 0) {
        return false;
    }
    return capabilities->e_vmcs_version == 0 ||
           (features & kCapEnlightenedVmcs) != 0;
}

bool HasFlag(const HvCapabilitySnapshot* capabilities, u32 flag) {
    return (capabilities->status_flags & flag) != 0;
}

bool HasFeature(const HvCapabilitySnapshot* capabilities, u64 feature) {
    return (capabilities->feature_bits & feature) != 0;
}

}  // namespace

HvStatus SelectProvider(const HvProviderRequest* request,
                        const HvCapabilitySnapshot* capabilities,
                        HvProviderKind* selected) {
    if (selected == nullptr || !RequestIsValid(request) ||
        !SnapshotIsValid(capabilities)) {
        return HvStatus::InvalidParameter;
    }
    *selected = HvProviderKind::None;

    const bool outer_l0 = HasFlag(capabilities, kFlagOuterL0Active);
    const bool native_ready = HasFlag(capabilities, kFlagNativeVmxReady);
    const bool boot_verified = HasFlag(capabilities, kFlagBootHandoffVerified);
    const bool knhv_l0 = HasFlag(capabilities, kFlagKnhvBootL0Active);
    const bool synthetic = HasFlag(capabilities, kFlagSyntheticSnapshot);
    const bool nested_vmx = HasFlag(capabilities, kFlagNestedVmx) &&
                            HasFeature(capabilities, kCapNestedVmx);
    const bool whp_partition = HasFlag(capabilities, kFlagWhpPartition) &&
                               HasFeature(capabilities, kCapWhpPartition);

    switch (request->mode) {
        case HvMode::BootL0Interposer:
            if (outer_l0) return HvStatus::HardwareOwnerConflict;
            if (!native_ready) return HvStatus::HardwareUnsupported;
            if (!boot_verified) return HvStatus::BootHandoffFailed;
            if ((request->requested_features & ~capabilities->feature_bits) !=
                0) {
                return HvStatus::CapabilityMismatch;
            }
            *selected = HvProviderKind::BootL0Interposer;
            return HvStatus::Success;

        case HvMode::CooperativeL1:
            if ((!knhv_l0 && !synthetic) || !nested_vmx ||
                request->identity_verified == 0) {
                return HvStatus::NestedUnavailable;
            }
            if ((request->requested_features & ~capabilities->feature_bits) !=
                0) {
                return HvStatus::CapabilityMismatch;
            }
            *selected = HvProviderKind::CooperativeL1;
            return HvStatus::Success;

        case HvMode::KnownLegacyCompat:
            if (!knhv_l0 || !nested_vmx ||
                request->legacy_manifest_match == 0) {
                *selected = HvProviderKind::LoadOnly;
                return HvStatus::LoadOnly;
            }
            *selected = HvProviderKind::KnownLegacyAdapter;
            return HvStatus::Success;

        case HvMode::LoadOnly:
            *selected = HvProviderKind::LoadOnly;
            return HvStatus::LoadOnly;

        case HvMode::ExternalL0Fallback:
            if (!outer_l0 || !whp_partition) {
                return HvStatus::UnsupportedMode;
            }
            *selected = HvProviderKind::ExternalL0Fallback;
            return HvStatus::Success;

        case HvMode::NativeExclusiveBaseline:
            if (outer_l0 || !native_ready) {
                return HvStatus::HardwareOwnerConflict;
            }
            *selected = HvProviderKind::NativeExclusiveBaseline;
            return HvStatus::Success;

        case HvMode::WhpClient:
            if (!whp_partition) return HvStatus::NestedUnavailable;
            *selected = HvProviderKind::WhpClient;
            return HvStatus::Success;

        default:
            return HvStatus::UnsupportedMode;
    }
}

HvCapabilitySnapshot MakeFallbackCapabilitySnapshot(bool outer_l0_active,
                                                     bool whp_available) {
    HvCapabilitySnapshot snapshot = {};
    snapshot.version = kAbiVersion;
    snapshot.size = sizeof(snapshot);
    snapshot.feature_bits = kCapVmx;
    snapshot.status_flags = 0;
    if (outer_l0_active) snapshot.status_flags |= kFlagOuterL0Active;
    if (whp_available) {
        snapshot.feature_bits |= kCapWhpPartition;
        snapshot.status_flags |= kFlagWhpPartition;
    }
    snapshot.max_physical_address_bits = 48U;
    snapshot.whp_api_version = whp_available ? 1U : 0U;
    return snapshot;
}

}  // namespace knhv
