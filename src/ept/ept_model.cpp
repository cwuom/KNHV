#include "knhv_ept.h"

namespace knhv {
namespace {

constexpr u64 kEptpMemoryTypeMask = 0x7ULL;
constexpr u64 kEptpWalkLengthMask = 0x38ULL;
constexpr u64 kEptpAccessDirtyBit = 1ULL << 6;
constexpr u64 kEptPhysicalAddressMask = 0x000FFFFFFFFFF000ULL;
constexpr u64 kEptpKnownMask = kEptPhysicalAddressMask | 0x7FULL;

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kEptContractVersion && size >= required &&
           size <= kEptMaxStructSize;
}

bool IsPhysicalAddress(u64 address, u32 bits) {
    return bits >= kEptPageShift && bits <= kEptMaxPhysicalAddressBits &&
           (address >> bits) == 0;
}

bool AddOverflow(u64 left, u64 right, u64* result) {
    if (result == nullptr || left > ~0ULL - right) return true;
    *result = left + right;
    return false;
}

bool MappingSpan(const EptMapping* mapping, u64* page_size,
                 u64* span_bytes) {
    if (mapping == nullptr || page_size == nullptr || span_bytes == nullptr ||
        mapping->page_count == 0 ||
        mapping->page_count > kEptMaxMappingPages || mapping->page_order > 2U) {
        return false;
    }
    *page_size = 1ULL << (kEptPageShift + (mapping->page_order * 9U));
    if (mapping->page_count > ~0ULL / *page_size) return false;
    *span_bytes = mapping->page_count * *page_size;
    return *span_bytes != 0;
}

bool IsHookKindValid(u32 value) {
    return value >= static_cast<u32>(EptHookKind::Execute) &&
           value <= static_cast<u32>(EptHookKind::Monitor);
}

EptLookupResult MakeLookup(EptLookupStatus status, u32 permissions, u64 hpa,
                           u64 generation) {
    EptLookupResult result = {};
    result.size = sizeof(result);
    result.version = kEptContractVersion;
    result.status = static_cast<u32>(status);
    result.permissions = permissions;
    result.host_physical = hpa;
    result.generation = generation;
    return result;
}

}  // namespace

bool IsEptpConfigValid(const EptpConfig* config, u32 max_physical_bits) {
    if (config == nullptr ||
        !IsVersionedSizeValid(config->version, config->size,
                              sizeof(EptpConfig)) ||
        config->reserved != 0 ||
        (config->flags & ~kEptpKnownFlagMask) != 0 ||
        (config->memory_type != kEptMemoryTypeUc &&
         config->memory_type != kEptMemoryTypeWb) ||
        config->walk_length < kEptMinWalkLength ||
        config->walk_length > kEptMaxWalkLength || config->generation == 0 ||
        !IsPhysicalAddress(config->root_physical, max_physical_bits) ||
        (config->root_physical & (kEptPageSize - 1ULL)) != 0) {
        return false;
    }
    return true;
}

bool BuildEptPointer(const EptpConfig* config, u64* raw_eptp) {
    if (raw_eptp == nullptr || config == nullptr ||
        !IsEptpConfigValid(config, kEptMaxPhysicalAddressBits)) {
        return false;
    }
    u64 value = config->root_physical & kEptPhysicalAddressMask;
    value |= static_cast<u64>(config->memory_type) & kEptpMemoryTypeMask;
    value |= static_cast<u64>(config->walk_length - 1U) << 3U;
    if ((config->flags & kEptpFlagAccessDirty) != 0) {
        value |= kEptpAccessDirtyBit;
    }
    *raw_eptp = value;
    return true;
}

bool DecodeEptPointer(u64 raw_eptp, EptpConfig* config) {
    const u64 memory_type = raw_eptp & kEptpMemoryTypeMask;
    if (config == nullptr || (raw_eptp & ~kEptpKnownMask) != 0 ||
        (memory_type != kEptMemoryTypeUc && memory_type != kEptMemoryTypeWb)) {
        return false;
    }
    const u32 walk_length =
        static_cast<u32>((raw_eptp & kEptpWalkLengthMask) >> 3U) + 1U;
    if (walk_length < kEptMinWalkLength || walk_length > kEptMaxWalkLength) {
        return false;
    }
    *config = {};
    config->size = sizeof(*config);
    config->version = kEptContractVersion;
    config->root_physical = raw_eptp & kEptPhysicalAddressMask;
    config->memory_type = static_cast<u32>(memory_type);
    config->walk_length = walk_length;
    config->flags = (raw_eptp & kEptpAccessDirtyBit) != 0
                        ? kEptpFlagAccessDirty
                        : 0U;
    return true;
}

bool IsEptMappingValid(const EptMapping* mapping, u32 max_physical_bits) {
    if (mapping == nullptr ||
        !IsVersionedSizeValid(mapping->version, mapping->size,
                              sizeof(EptMapping)) ||
        (mapping->flags & ~kEptMappingKnownFlagMask) != 0 ||
        (mapping->flags & kEptMappingFlagPresent) == 0 ||
        (mapping->permissions & ~kEptPermissionKnownMask) != 0 ||
        mapping->permissions == 0 ||
        (mapping->memory_type != kEptMemoryTypeUc &&
         mapping->memory_type != kEptMemoryTypeWb) ||
        mapping->generation == 0) {
        return false;
    }
    u64 page_size = 0;
    u64 span_bytes = 0;
    if (!MappingSpan(mapping, &page_size, &span_bytes) ||
        (mapping->guest_physical & (page_size - 1ULL)) != 0 ||
        (mapping->host_physical & (page_size - 1ULL)) != 0 ||
        (mapping->page_order == 0 &&
         (mapping->flags & kEptMappingFlagLargePage) != 0) ||
        (mapping->page_order != 0 &&
         (mapping->flags & kEptMappingFlagLargePage) == 0) ||
        !IsPhysicalAddress(mapping->guest_physical, max_physical_bits) ||
        !IsPhysicalAddress(mapping->host_physical, max_physical_bits)) {
        return false;
    }
    u64 last_guest = 0;
    u64 last_host = 0;
    if (AddOverflow(mapping->guest_physical, span_bytes - 1ULL,
                    &last_guest) ||
        AddOverflow(mapping->host_physical, span_bytes - 1ULL, &last_host) ||
        !IsPhysicalAddress(last_guest, max_physical_bits) ||
        !IsPhysicalAddress(last_host, max_physical_bits)) {
        return false;
    }
    return true;
}

bool EptMappingContains(const EptMapping* mapping, u64 guest_physical) {
    if (!IsEptMappingValid(mapping, kEptMaxPhysicalAddressBits)) return false;
    u64 page_size = 0;
    u64 span_bytes = 0;
    if (!MappingSpan(mapping, &page_size, &span_bytes)) return false;
    if (guest_physical < mapping->guest_physical) return false;
    const u64 offset = guest_physical - mapping->guest_physical;
    return offset < span_bytes;
}

bool IsEptAccessAllowed(u32 permissions, EptAccess access) {
    u32 required = 0;
    switch (access) {
        case EptAccess::Read:
            required = kEptPermissionRead;
            break;
        case EptAccess::Write:
            required = kEptPermissionWrite;
            break;
        case EptAccess::Execute:
            required = kEptPermissionExecute;
            break;
        default:
            return false;
    }
    return (permissions & required) != 0;
}

EptLookupResult ResolveNestedEpt(const EptMapping* l1_mapping,
                                 const EptMapping* root_mapping,
                                 u64 l2_guest_physical, EptAccess access) {
    if (!IsEptMappingValid(l1_mapping, kEptMaxPhysicalAddressBits) ||
        !IsEptMappingValid(root_mapping, kEptMaxPhysicalAddressBits)) {
        return MakeLookup(EptLookupStatus::Invalid, 0, 0, 0);
    }
    if (l1_mapping->generation != root_mapping->generation) {
        return MakeLookup(EptLookupStatus::Stale, 0, 0,
                          root_mapping->generation);
    }
    if (!EptMappingContains(l1_mapping, l2_guest_physical)) {
        return MakeLookup(EptLookupStatus::NotPresent, 0, 0,
                          root_mapping->generation);
    }
    if (!IsEptAccessAllowed(l1_mapping->permissions, access)) {
        return MakeLookup(EptLookupStatus::PermissionDenied, 0, 0,
                          root_mapping->generation);
    }
    const u64 l1_offset = l2_guest_physical - l1_mapping->guest_physical;
    u64 l1_guest_physical = 0;
    if (AddOverflow(l1_mapping->host_physical, l1_offset,
                    &l1_guest_physical)) {
        return MakeLookup(EptLookupStatus::Invalid, 0, 0,
                          root_mapping->generation);
    }
    if (!EptMappingContains(root_mapping, l1_guest_physical)) {
        return MakeLookup(EptLookupStatus::NotPresent, 0, 0,
                          root_mapping->generation);
    }
    if ((root_mapping->flags & kEptMappingFlagHostOwned) != 0) {
        return MakeLookup(EptLookupStatus::HostOwned, 0, 0,
                          root_mapping->generation);
    }
    if (!IsEptAccessAllowed(root_mapping->permissions, access)) {
        return MakeLookup(EptLookupStatus::PermissionDenied, 0, 0,
                          root_mapping->generation);
    }
    const u64 root_offset = l1_guest_physical - root_mapping->guest_physical;
    u64 host_physical = 0;
    if (AddOverflow(root_mapping->host_physical, root_offset,
                    &host_physical)) {
        return MakeLookup(EptLookupStatus::Invalid, 0, 0,
                          root_mapping->generation);
    }
    return MakeLookup(EptLookupStatus::Hit,
                      l1_mapping->permissions & root_mapping->permissions,
                      host_physical, root_mapping->generation);
}

bool IsEptHookLeaseValid(const EptHookLease* lease) {
    if (lease == nullptr ||
        !IsVersionedSizeValid(lease->version, lease->size,
                              sizeof(EptHookLease)) ||
        lease->owner_id == 0 || lease->generation == 0 ||
        lease->expires_tsc == 0 ||
        lease->view != static_cast<u32>(EptViewKind::GuestDebug) ||
        !IsHookKindValid(lease->hook_kind) ||
        lease->state != static_cast<u32>(EptHookState::Active) ||
        lease->max_pages == 0 || lease->max_pages > kEptMaxMappingPages ||
        lease->max_exits_per_second == 0 || lease->reserved != 0) {
        return false;
    }
    return true;
}

bool IsEptHookRequestValid(const EptHookRequest* request) {
    if (request == nullptr ||
        !IsVersionedSizeValid(request->version, request->size,
                              sizeof(EptHookRequest)) ||
        request->owner_id == 0 || request->expected_generation == 0 ||
        request->guest_physical % kEptPageSize != 0 ||
        request->page_count == 0 || request->page_count > kEptMaxMappingPages ||
        request->view != static_cast<u32>(EptViewKind::GuestDebug) ||
        !IsHookKindValid(request->hook_kind) ||
        (request->permissions & ~kEptPermissionKnownMask) != 0 ||
        request->permissions == 0 || request->reserved != 0 ||
        (request->module_hash[0] == 0 && request->module_hash[1] == 0)) {
        return false;
    }
    return true;
}

bool CanPublishEptHook(const EptHookLease* lease,
                       const EptHookRequest* request,
                       u64 current_generation, u64 now_tsc) {
    return IsEptHookLeaseValid(lease) && IsEptHookRequestValid(request) &&
           current_generation != 0 && lease->owner_id == request->owner_id &&
           lease->generation == current_generation &&
           request->expected_generation == current_generation &&
           lease->hook_kind == request->hook_kind &&
           now_tsc < lease->expires_tsc &&
           request->page_count <= lease->max_pages;
}

bool NextEptGeneration(u64 current_generation, u64* next_generation) {
    if (next_generation == nullptr || current_generation == ~0ULL) {
        return false;
    }
    *next_generation = current_generation == 0 ? 1ULL : current_generation + 1ULL;
    return true;
}

bool BeginEptGeneration(const EptGeneration* current,
                        EptGeneration* pending) {
    if (current == nullptr || pending == nullptr ||
        !IsVersionedSizeValid(current->version, current->size,
                              sizeof(EptGeneration)) ||
        current->state != static_cast<u32>(EptGenerationState::Active) ||
        current->generation == 0 || current->reserved != 0) {
        return false;
    }
    u64 next = 0;
    if (!NextEptGeneration(current->generation, &next)) return false;
    *pending = {};
    pending->size = sizeof(*pending);
    pending->version = kEptContractVersion;
    pending->generation = next;
    pending->parent_generation = current->generation;
    pending->state = static_cast<u32>(EptGenerationState::Pending);
    return true;
}

bool AcknowledgeEptGeneration(EptGeneration* pending, u32 cpu_count) {
    if (pending == nullptr ||
        !IsVersionedSizeValid(pending->version, pending->size,
                              sizeof(EptGeneration)) ||
        pending->state != static_cast<u32>(EptGenerationState::Pending) ||
        cpu_count == 0 || pending->required_cpu_acks == 0 ||
        pending->observed_cpu_acks > pending->required_cpu_acks ||
        cpu_count > pending->required_cpu_acks - pending->observed_cpu_acks) {
        return false;
    }
    pending->observed_cpu_acks += cpu_count;
    return true;
}

bool PublishEptGeneration(EptGeneration* pending) {
    if (pending == nullptr ||
        !IsVersionedSizeValid(pending->version, pending->size,
                              sizeof(EptGeneration)) ||
        pending->state != static_cast<u32>(EptGenerationState::Pending) ||
        pending->required_cpu_acks == 0 ||
        pending->observed_cpu_acks != pending->required_cpu_acks) {
        return false;
    }
    pending->state = static_cast<u32>(EptGenerationState::Active);
    return true;
}

}  // namespace knhv
