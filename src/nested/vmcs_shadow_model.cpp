#include "knhv_vmcs_shadow.h"

#include "nested_internal.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kVmcsShadowContractVersion && size >= required &&
           size <= kVmcsShadowMaxStructSize;
}

bool IsPhysicalPage(u64 address, u32 bits) {
    return address != 0 && address != kVmcsShadowNoLinkPointer &&
           (address & (kVmcsShadowPageSize - 1ULL)) == 0 && bits >= 12U &&
           bits <= kVmcsShadowMaxPhysicalAddressBits && (address >> bits) == 0;
}

bool IsStateValid(u32 state) {
    return state <= static_cast<u32>(VmcsShadowState::Quarantined);
}

bool IsOperationValid(u32 operation) {
    return operation ==
               static_cast<u32>(VmcsShadowAccessOperation::Read) ||
           operation ==
               static_cast<u32>(VmcsShadowAccessOperation::Write);
}

bool IsBitSet(const u8* bitmap, u32 field_index) {
    if (bitmap == nullptr || field_index >= kVmcsShadowMaxFields) return false;
    return (bitmap[field_index / 8U] &
            static_cast<u8>(1U << (field_index % 8U))) != 0;
}

bool BitmapTailIsClear(const u8* bitmap, u32 field_count) {
    if (bitmap == nullptr || field_count > kVmcsShadowMaxFields) return false;
    for (u32 index = field_count; index < kVmcsShadowMaxFields; ++index) {
        if (IsBitSet(bitmap, index)) return false;
    }
    return true;
}

bool BitmapIsZero(const u8* bitmap) {
    if (bitmap == nullptr) return false;
    for (u32 index = 0; index < kVmcsShadowBitmapBytes; ++index) {
        if (bitmap[index] != 0) return false;
    }
    return true;
}

bool ConfigMatchesCapabilities(const VmcsShadowCapabilities* capabilities,
                               const VmcsShadowConfig* config) {
    if (capabilities == nullptr || config == nullptr ||
        config->generation != capabilities->generation) {
        return false;
    }
    if ((config->flags & kVmcsShadowEnableLinkPointer) != 0 &&
        (capabilities->feature_flags & kVmcsShadowCapLinkPointer) == 0) {
        return false;
    }
    if ((config->flags & kVmcsShadowEnableReadBitmap) != 0 &&
        (capabilities->feature_flags & kVmcsShadowCapReadBitmap) == 0) {
        return false;
    }
    if ((config->flags & kVmcsShadowEnableWriteBitmap) != 0 &&
        (capabilities->feature_flags & kVmcsShadowCapWriteBitmap) == 0) {
        return false;
    }
    return (capabilities->feature_flags & kVmcsShadowCapSupported) != 0;
}

const nested_internal::FieldRule* ResolveField(const VmcsShadowAccess* access) {
    if (access == nullptr) return nullptr;
    const nested_internal::FieldRule* rule =
        nested_internal::FindFieldRule(access->encoding);
    if (rule == nullptr ||
        nested_internal::FieldIndex(rule) != access->field_index) {
        return nullptr;
    }
    return rule;
}

u64 FieldMask(const nested_internal::FieldRule& rule) {
    if (rule.width == 2U) return 0xFFFFULL;
    if (rule.width == 4U) return 0xFFFFFFFFULL;
    if (rule.width == 8U) return ~0ULL;
    return 0;
}

void InitializeDecision(const VmcsShadowAccess* access, u64 generation,
                        VmcsShadowDecision* decision) {
    *decision = {};
    decision->size = sizeof(*decision);
    decision->version = kVmcsShadowContractVersion;
    decision->result =
        static_cast<u32>(VmcsShadowAccessResult::Invalid);
    decision->field_index = access == nullptr ? 0U : access->field_index;
    decision->generation = generation;
}

void SetDecision(VmcsShadowDecision* decision, VmcsShadowAccessResult result,
                 u64 value) {
    decision->result = static_cast<u32>(result);
    decision->value = value;
}

}  // namespace

bool IsVmcsShadowCapabilitiesValid(
    const VmcsShadowCapabilities* capabilities) {
    return capabilities != nullptr &&
           IsVersionedSizeValid(capabilities->version, capabilities->size,
                                sizeof(VmcsShadowCapabilities)) &&
           (capabilities->feature_flags &
            ~kVmcsShadowKnownCapabilityMask) == 0 &&
           (capabilities->feature_flags & kVmcsShadowCapSupported) != 0 &&
           capabilities->max_fields != 0 &&
           capabilities->max_fields <= kVmcsShadowMaxFields &&
           capabilities->physical_address_bits >= 12U &&
           capabilities->physical_address_bits <=
               kVmcsShadowMaxPhysicalAddressBits &&
           capabilities->generation != 0 && capabilities->reserved == 0;
}

bool IsVmcsShadowConfigValid(const VmcsShadowConfig* config,
                             u32 max_physical_address_bits,
                             u32 max_fields) {
    if (config == nullptr ||
        !IsVersionedSizeValid(config->version, config->size,
                              sizeof(VmcsShadowConfig)) ||
        max_physical_address_bits < 12U ||
        max_physical_address_bits > kVmcsShadowMaxPhysicalAddressBits ||
        max_fields == 0 || max_fields > kVmcsShadowMaxFields ||
        (config->flags & ~kVmcsShadowKnownConfigFlagMask) != 0 ||
        config->reserved != 0 || config->generation == 0 ||
        !BitmapTailIsClear(config->read_bitmap, max_fields) ||
        !BitmapTailIsClear(config->write_bitmap, max_fields)) {
        return false;
    }
    const bool link_enabled =
        (config->flags & kVmcsShadowEnableLinkPointer) != 0;
    const bool read_enabled =
        (config->flags & kVmcsShadowEnableReadBitmap) != 0;
    const bool write_enabled =
        (config->flags & kVmcsShadowEnableWriteBitmap) != 0;
    if (link_enabled
            ? !IsPhysicalPage(config->link_pointer,
                              max_physical_address_bits)
            : config->link_pointer != kVmcsShadowNoLinkPointer) {
        return false;
    }
    if (read_enabled
            ? !IsPhysicalPage(config->read_bitmap_physical,
                              max_physical_address_bits)
            : config->read_bitmap_physical != kVmcsShadowNoLinkPointer) {
        return false;
    }
    if (write_enabled
            ? !IsPhysicalPage(config->write_bitmap_physical,
                              max_physical_address_bits)
            : config->write_bitmap_physical != kVmcsShadowNoLinkPointer) {
        return false;
    }
    if (!read_enabled && !BitmapIsZero(config->read_bitmap)) return false;
    if (!write_enabled && !BitmapIsZero(config->write_bitmap)) return false;
    return true;
}

bool IsVmcsShadowImageValid(const VmcsShadowImage* image) {
    if (image == nullptr ||
        !IsVersionedSizeValid(image->version, image->size,
                              sizeof(VmcsShadowImage)) ||
        !IsStateValid(image->state) || image->reserved[0] != 0 ||
        image->reserved[1] != 0) {
        return false;
    }
    const auto state = static_cast<VmcsShadowState>(image->state);
    if (state == VmcsShadowState::Empty) {
        return image->generation == 0 && image->field_count == 0;
    }
    if (image->generation == 0 || image->field_count == 0 ||
        image->field_count > kVmcsShadowMaxFields ||
        !BitmapTailIsClear(reinterpret_cast<const u8*>(image->dirty_bitmap),
                           image->field_count)) {
        return false;
    }
    return true;
}

bool IsVmcsShadowAccessValid(const VmcsShadowAccess* access) {
    return access != nullptr &&
           IsVersionedSizeValid(access->version, access->size,
                                sizeof(VmcsShadowAccess)) &&
           access->field_index < kVmcsShadowMaxFields &&
           IsOperationValid(access->operation) && access->reserved == 0 &&
           access->generation != 0 && ResolveField(access) != nullptr;
}

bool BeginVmcsShadow(const VmcsShadowCapabilities* capabilities,
                     const VmcsShadowConfig* config,
                     VmcsShadowImage* image) {
    if (image == nullptr) return false;
    *image = {};
    if (!IsVmcsShadowCapabilitiesValid(capabilities) ||
        !IsVmcsShadowConfigValid(config, capabilities->physical_address_bits,
                                 capabilities->max_fields) ||
        !ConfigMatchesCapabilities(capabilities, config)) {
        return false;
    }
    image->size = sizeof(*image);
    image->version = kVmcsShadowContractVersion;
    image->generation = config->generation;
    image->state = static_cast<u32>(VmcsShadowState::Active);
    image->field_count = capabilities->max_fields;
    return IsVmcsShadowImageValid(image);
}

bool ClearVmcsShadow(VmcsShadowImage* image, u64 generation) {
    if (!IsVmcsShadowImageValid(image) ||
        image->state != static_cast<u32>(VmcsShadowState::Active) ||
        generation == 0 || image->generation != generation) {
        return false;
    }
    image->state = static_cast<u32>(VmcsShadowState::Cleared);
    return true;
}

bool RebindVmcsShadow(const VmcsShadowCapabilities* capabilities,
                      const VmcsShadowConfig* config,
                      u64 expected_generation, VmcsShadowImage* image) {
    if (!IsVmcsShadowImageValid(image) ||
        image->state != static_cast<u32>(VmcsShadowState::Cleared) ||
        expected_generation == 0 || expected_generation <= image->generation ||
        !IsVmcsShadowCapabilitiesValid(capabilities) ||
        !IsVmcsShadowConfigValid(config, capabilities->physical_address_bits,
                                 capabilities->max_fields) ||
        config->generation != expected_generation ||
        !ConfigMatchesCapabilities(capabilities, config)) {
        return false;
    }
    return BeginVmcsShadow(capabilities, config, image);
}

bool QuarantineVmcsShadow(VmcsShadowImage* image, u64 generation) {
    if (!IsVmcsShadowImageValid(image) || generation == 0 ||
        image->generation != generation ||
        (image->state != static_cast<u32>(VmcsShadowState::Active) &&
         image->state != static_cast<u32>(VmcsShadowState::Cleared))) {
        return false;
    }
    image->state = static_cast<u32>(VmcsShadowState::Quarantined);
    return true;
}

VmcsShadowAccessResult ClassifyVmcsShadowAccess(
    const VmcsShadowCapabilities* capabilities,
    const VmcsShadowConfig* config, const VmcsShadowImage* image,
    const VmcsShadowAccess* access, u64 generation,
    VmcsShadowDecision* decision) {
    if (decision == nullptr) return VmcsShadowAccessResult::Invalid;
    InitializeDecision(access, generation, decision);
    if (!IsVmcsShadowCapabilitiesValid(capabilities) ||
        !IsVmcsShadowConfigValid(config, capabilities->physical_address_bits,
                                 capabilities->max_fields) ||
        !ConfigMatchesCapabilities(capabilities, config) ||
        !IsVmcsShadowImageValid(image) || !IsVmcsShadowAccessValid(access)) {
        return VmcsShadowAccessResult::Invalid;
    }
    if (generation == 0 || generation != config->generation ||
        generation != image->generation || generation != access->generation) {
        SetDecision(decision, VmcsShadowAccessResult::Stale, 0);
        return VmcsShadowAccessResult::Stale;
    }
    if (image->state == static_cast<u32>(VmcsShadowState::Quarantined)) {
        SetDecision(decision, VmcsShadowAccessResult::Quarantined, 0);
        return VmcsShadowAccessResult::Quarantined;
    }
    if (image->state != static_cast<u32>(VmcsShadowState::Active) ||
        access->field_index >= image->field_count) {
        return VmcsShadowAccessResult::Invalid;
    }
    const nested_internal::FieldRule* rule = ResolveField(access);
    if (rule == nullptr) return VmcsShadowAccessResult::Invalid;
    const bool write =
        access->operation == static_cast<u32>(VmcsShadowAccessOperation::Write);
    if (write && rule->writable == 0) {
        SetDecision(decision, VmcsShadowAccessResult::ReflectExit, 0);
        return VmcsShadowAccessResult::ReflectExit;
    }
    const bool bitmap_enabled = write
                                    ? (config->flags &
                                       kVmcsShadowEnableWriteBitmap) != 0
                                    : (config->flags &
                                       kVmcsShadowEnableReadBitmap) != 0;
    const u8* bitmap = write ? config->write_bitmap : config->read_bitmap;
    if (!bitmap_enabled || IsBitSet(bitmap, access->field_index)) {
        SetDecision(decision, VmcsShadowAccessResult::ReflectExit, 0);
        return VmcsShadowAccessResult::ReflectExit;
    }
    SetDecision(decision, VmcsShadowAccessResult::Shadow, 0);
    return VmcsShadowAccessResult::Shadow;
}

VmcsShadowAccessResult ApplyVmcsShadowAccess(
    const VmcsShadowCapabilities* capabilities,
    const VmcsShadowConfig* config, VmcsShadowImage* image,
    const VmcsShadowAccess* access, u64 generation,
    VmcsShadowDecision* decision) {
    const VmcsShadowAccessResult result = ClassifyVmcsShadowAccess(
        capabilities, config, image, access, generation, decision);
    if (result != VmcsShadowAccessResult::Shadow) return result;
    const nested_internal::FieldRule* rule = ResolveField(access);
    if (rule == nullptr || decision == nullptr) {
        return VmcsShadowAccessResult::Invalid;
    }
    const u64 mask = FieldMask(*rule);
    if (mask == 0 || access->field_index >= image->field_count) {
        decision->result =
            static_cast<u32>(VmcsShadowAccessResult::Invalid);
        return VmcsShadowAccessResult::Invalid;
    }
    const bool write =
        access->operation == static_cast<u32>(VmcsShadowAccessOperation::Write);
    if (write) {
        image->fields[access->field_index] = access->value & mask;
        image->dirty_bitmap[access->field_index / 64U] |=
            1ULL << (access->field_index % 64U);
        decision->value = image->fields[access->field_index];
    } else {
        decision->value = image->fields[access->field_index] & mask;
    }
    return result;
}

}  // namespace knhv
