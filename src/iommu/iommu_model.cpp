#include "knhv_iommu.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kIommuContractVersion && size >= required &&
           size <= kIommuMaxStructSize;
}

bool IsAddressBitsValid(u32 bits) {
    return bits >= kIommuPageShift && bits <= kIommuMaxPhysicalAddressBits;
}

bool IsPhysicalAddress(u64 value, u32 bits) {
    return IsAddressBitsValid(bits) && (value >> bits) == 0;
}

bool AddOverflow(u64 left, u64 right, u64* result) {
    if (result == nullptr || left > ~0ULL - right) return true;
    *result = left + right;
    return false;
}

bool IsEnumValueValid(u32 value, u32 first, u32 last) {
    return value >= first && value <= last;
}

bool IsDomainKindValid(u32 value) {
    return IsEnumValueValid(value,
                            static_cast<u32>(IommuDomainKind::Host),
                            static_cast<u32>(IommuDomainKind::Quarantine));
}

bool IsDomainStateValid(u32 value) {
    return value <= static_cast<u32>(IommuDomainState::Retired);
}

bool IsResetMethodValid(u32 value) {
    return value <= static_cast<u32>(IommuResetMethod::SecondaryBus);
}

bool IsDmaAccessValid(u32 value) {
    return value == static_cast<u32>(IommuDmaAccess::Read) ||
           value == static_cast<u32>(IommuDmaAccess::Write);
}

bool IsFaultReasonValid(u32 value) {
    return IsEnumValueValid(value,
                            static_cast<u32>(IommuFaultReason::InvalidAddress),
                            static_cast<u32>(IommuFaultReason::Unknown));
}

bool IsReadinessValid(u32 readiness, u32 required) {
    return (readiness & ~kIommuKnownReadyMask) == 0 &&
           (readiness & required) == required;
}

bool IsSameBdf(const IommuBdf& left, const IommuBdf& right) {
    return left.segment == right.segment && left.bus == right.bus &&
           left.device == right.device && left.function == right.function;
}

bool IsRangeEndValid(u64 base, u64 length, u32 address_bits, u64* last) {
    if (length == 0 || (base & (kIommuPageSize - 1ULL)) != 0 ||
        (length & (kIommuPageSize - 1ULL)) != 0 ||
        AddOverflow(base, length - 1ULL, last)) {
        return false;
    }
    return IsPhysicalAddress(base, address_bits) &&
           IsPhysicalAddress(*last, address_bits);
}

bool MappingSpan(const IommuDmaMapping* mapping, u64* page_size,
                 u64* span_bytes) {
    if (mapping == nullptr || page_size == nullptr || span_bytes == nullptr ||
        mapping->page_count == 0 ||
        mapping->page_count > kIommuMaxMappingPages ||
        mapping->page_order > 2U) {
        return false;
    }
    *page_size = 1ULL << (kIommuPageShift + mapping->page_order * 9U);
    if (mapping->page_count > ~0ULL / *page_size) return false;
    *span_bytes = mapping->page_count * *page_size;
    return *span_bytes != 0;
}

IommuDmaResult MakeDmaResult(IommuLookupStatus status, u32 permissions,
                             u64 host_physical, u64 generation) {
    IommuDmaResult result = {};
    result.size = sizeof(result);
    result.version = kIommuContractVersion;
    result.status = static_cast<u32>(status);
    result.permissions = permissions;
    result.host_physical = host_physical;
    result.generation = generation;
    return result;
}

bool IsAssignmentValid(const IommuAssignment* assignment) {
    return assignment != nullptr &&
           IsVersionedSizeValid(assignment->version, assignment->size,
                                sizeof(IommuAssignment)) &&
           IsIommuBdfValid(&assignment->bdf) &&
           IsResetMethodValid(assignment->reset_method) &&
           (assignment->flags & ~kIommuKnownAssignmentMask) == 0 &&
           IsDomainStateValid(assignment->state) &&
           assignment->state != static_cast<u32>(IommuDomainState::Empty) &&
           assignment->owner_id != 0 && assignment->domain_id != 0 &&
           assignment->generation != 0;
}

void SetAssignmentStatus(IommuAssignment* assignment,
                         IommuAssignmentStatus status) {
    if (assignment == nullptr) return;
    assignment->status = static_cast<u32>(status);
    assignment->state = static_cast<u32>(IommuDomainState::Empty);
}

}  // namespace

bool IsIommuBdfValid(const IommuBdf* bdf) {
    if (bdf == nullptr || bdf->device >= 32U || bdf->function >= 8U) {
        return false;
    }
    return bdf->reserved[0] == 0 && bdf->reserved[1] == 0 &&
           bdf->reserved[2] == 0;
}

bool IsIommuRangeValid(const IommuRange* range, u32 address_bits) {
    if (range == nullptr || range->flags != 0 || range->reserved != 0) {
        return false;
    }
    u64 last = 0;
    return IsRangeEndValid(range->base, range->length, address_bits, &last);
}

bool IsIommuCapabilitiesValid(const IommuCapabilities* capabilities) {
    if (capabilities == nullptr ||
        !IsVersionedSizeValid(capabilities->version, capabilities->size,
                              sizeof(IommuCapabilities)) ||
        (capabilities->feature_flags & ~kIommuKnownCapabilityMask) != 0 ||
        !IsAddressBitsValid(capabilities->max_physical_address_bits) ||
        !IsAddressBitsValid(capabilities->max_domain_address_bits) ||
        capabilities->max_domain_address_bits >
            capabilities->max_physical_address_bits ||
        capabilities->max_domains == 0 ||
        capabilities->max_msix_vectors == 0 ||
        capabilities->max_msix_vectors > kIommuMaxMsixVectors ||
        capabilities->max_reserved_ranges > kIommuMaxReservedRanges ||
        capabilities->reserved != 0 || capabilities->generation == 0) {
        return false;
    }
    return true;
}

bool IsIommuDeviceProfileValid(const IommuDeviceProfile* profile,
                               u32 address_bits) {
    if (profile == nullptr ||
        !IsVersionedSizeValid(profile->version, profile->size,
                              sizeof(IommuDeviceProfile)) ||
        !IsIommuBdfValid(&profile->bdf) ||
        (profile->flags & ~kIommuKnownDeviceMask) != 0 ||
        !IsResetMethodValid(profile->reset_method) ||
        !IsAddressBitsValid(address_bits) ||
        profile->dma_address_bits < kIommuPageShift ||
        profile->dma_address_bits > address_bits ||
        profile->dma_address_bits > kIommuMaxPhysicalAddressBits ||
        profile->rmrr_count > kIommuMaxReservedRanges ||
        profile->profile_generation == 0 || profile->reserved != 0 ||
        profile->reserved2 != 0) {
        return false;
    }
    const u64 expected_mask = (1ULL << profile->dma_address_bits) - 1ULL;
    if (profile->dma_mask != expected_mask) return false;

    const bool reset_flag =
        (profile->flags & kIommuDeviceResetReliable) != 0;
    if (reset_flag !=
        (profile->reset_method != static_cast<u32>(IommuResetMethod::None))) {
        return false;
    }
    const bool rmrr_flag = (profile->flags & kIommuDeviceHasRmrr) != 0;
    if (rmrr_flag != (profile->rmrr_count != 0)) return false;
    const bool msix_flag = (profile->flags & kIommuDeviceMsix) != 0;
    if (msix_flag) {
        if (profile->max_msix_vectors == 0 ||
            profile->max_msix_vectors > kIommuMaxMsixVectors) {
            return false;
        }
    } else if (profile->max_msix_vectors != 0) {
        return false;
    }
    if ((profile->flags & kIommuDeviceIsolationComplete) != 0 &&
        profile->isolation_group == 0) {
        return false;
    }
    if ((profile->flags & kIommuDeviceHasRmrr) == 0 &&
        profile->rmrr_count != 0) {
        return false;
    }
    for (u32 index = 0; index < kIommuMaxReservedRanges; ++index) {
        const IommuRange& range = profile->rmrr[index];
        if (index < profile->rmrr_count) {
            if (!IsIommuRangeValid(&range, address_bits)) return false;
        } else if (range.base != 0 || range.length != 0 || range.flags != 0 ||
                   range.reserved != 0) {
            return false;
        }
    }
    return true;
}

bool IsIommuDomainValid(const IommuDomain* domain, u32 address_bits) {
    if (domain == nullptr ||
        !IsVersionedSizeValid(domain->version, domain->size,
                              sizeof(IommuDomain)) ||
        domain->domain_id == 0 || !IsDomainKindValid(domain->kind) ||
        !IsDomainStateValid(domain->state) ||
        (domain->flags & ~kIommuKnownDomainMask) != 0 ||
        !IsAddressBitsValid(address_bits) ||
        domain->address_bits < kIommuPageShift ||
        domain->address_bits > address_bits || domain->generation == 0 ||
        domain->guest_base > domain->guest_limit ||
        !IsPhysicalAddress(domain->guest_base, domain->address_bits) ||
        !IsPhysicalAddress(domain->guest_limit, domain->address_bits) ||
        (domain->guest_base & (kIommuPageSize - 1ULL)) != 0 ||
        domain->mapped_pages > kIommuMaxMappingPages ||
        domain->reserved != 0 || domain->reserved2 != 0) {
        return false;
    }
    const auto kind = static_cast<IommuDomainKind>(domain->kind);
    const auto state = static_cast<IommuDomainState>(domain->state);
    if (kind == IommuDomainKind::Host) {
        if (domain->owner_id != 0 || domain->parent_domain_id != 0 ||
            (domain->flags & kIommuDomainIdentity) == 0 ||
            state != IommuDomainState::Active) {
            return false;
        }
    } else if (kind == IommuDomainKind::L1) {
        if (domain->owner_id == 0 ||
            (domain->flags & kIommuDomainInterruptRemap) == 0 ||
            (domain->flags & kIommuDomainNested) != 0 ||
            state == IommuDomainState::Empty) {
            return false;
        }
    } else if (kind == IommuDomainKind::L2) {
        if (domain->owner_id == 0 || domain->parent_domain_id == 0 ||
            (domain->flags & kIommuDomainNested) == 0 ||
            (domain->flags & kIommuDomainInterruptRemap) == 0 ||
            state == IommuDomainState::Empty) {
            return false;
        }
    } else if (kind == IommuDomainKind::Quarantine) {
        if (state != IommuDomainState::Quarantined) return false;
    }
    return true;
}

bool IsIommuDmaMappingValid(const IommuDmaMapping* mapping,
                            u32 address_bits) {
    if (mapping == nullptr ||
        !IsVersionedSizeValid(mapping->version, mapping->size,
                              sizeof(IommuDmaMapping)) ||
        (mapping->flags & ~kIommuKnownMappingMask) != 0 ||
        (mapping->flags & kIommuMappingPresent) == 0 ||
        (mapping->flags & kIommuMappingPinned) == 0 ||
        (mapping->permissions & ~kIommuKnownPermissionMask) != 0 ||
        mapping->permissions == 0 || mapping->reserved != 0 ||
        mapping->generation == 0 || !IsAddressBitsValid(address_bits)) {
        return false;
    }
    u64 page_size = 0;
    u64 span_bytes = 0;
    if (!MappingSpan(mapping, &page_size, &span_bytes) ||
        (mapping->iova & (page_size - 1ULL)) != 0 ||
        (mapping->guest_physical & (page_size - 1ULL)) != 0 ||
        (mapping->host_physical & (page_size - 1ULL)) != 0 ||
        (mapping->page_order == 0 &&
         (mapping->flags & kIommuMappingLargePage) != 0) ||
        (mapping->page_order != 0 &&
         (mapping->flags & kIommuMappingLargePage) == 0) ||
        !IsPhysicalAddress(mapping->iova, address_bits) ||
        !IsPhysicalAddress(mapping->guest_physical, address_bits) ||
        !IsPhysicalAddress(mapping->host_physical, address_bits)) {
        return false;
    }
    u64 last_iova = 0;
    u64 last_guest = 0;
    u64 last_host = 0;
    return !AddOverflow(mapping->iova, span_bytes - 1ULL, &last_iova) &&
           !AddOverflow(mapping->guest_physical, span_bytes - 1ULL,
                        &last_guest) &&
           !AddOverflow(mapping->host_physical, span_bytes - 1ULL, &last_host) &&
           IsPhysicalAddress(last_iova, address_bits) &&
           IsPhysicalAddress(last_guest, address_bits) &&
           IsPhysicalAddress(last_host, address_bits);
}

bool IommuDmaMappingContains(const IommuDmaMapping* mapping, u64 iova,
                             u32 address_bits) {
    if (!IsIommuDmaMappingValid(mapping, address_bits)) return false;
    u64 page_size = 0;
    u64 span_bytes = 0;
    if (!MappingSpan(mapping, &page_size, &span_bytes) ||
        iova < mapping->iova) {
        return false;
    }
    return iova - mapping->iova < span_bytes;
}

bool IsIommuDmaAccessAllowed(u32 permissions, IommuDmaAccess access) {
    u32 required = 0;
    switch (access) {
        case IommuDmaAccess::Read:
            required = kIommuPermissionRead;
            break;
        case IommuDmaAccess::Write:
            required = kIommuPermissionWrite;
            break;
        default:
            return false;
    }
    return (permissions & required) != 0;
}

IommuDmaResult ResolveNestedDma(const IommuDmaMapping* l1_mapping,
                                const IommuDmaMapping* root_mapping,
                                u64 iova, IommuDmaAccess access,
                                u32 address_bits) {
    if (!IsIommuDmaMappingValid(l1_mapping, address_bits) ||
        !IsIommuDmaMappingValid(root_mapping, address_bits)) {
        return MakeDmaResult(IommuLookupStatus::Invalid, 0, 0, 0);
    }
    if (l1_mapping->generation != root_mapping->generation) {
        return MakeDmaResult(IommuLookupStatus::Stale, 0, 0,
                             root_mapping->generation);
    }
    if ((l1_mapping->flags & kIommuMappingHostOwned) != 0) {
        return MakeDmaResult(IommuLookupStatus::HostOwned, 0, 0,
                             root_mapping->generation);
    }
    if (!IommuDmaMappingContains(l1_mapping, iova, address_bits)) {
        return MakeDmaResult(IommuLookupStatus::NotPresent, 0, 0,
                             root_mapping->generation);
    }
    if (!IsIommuDmaAccessAllowed(l1_mapping->permissions, access)) {
        return MakeDmaResult(IommuLookupStatus::PermissionDenied, 0, 0,
                             root_mapping->generation);
    }
    const u64 l1_offset = iova - l1_mapping->iova;
    u64 guest_physical = 0;
    if (AddOverflow(l1_mapping->guest_physical, l1_offset,
                    &guest_physical)) {
        return MakeDmaResult(IommuLookupStatus::Invalid, 0, 0,
                             root_mapping->generation);
    }
    if (!IommuDmaMappingContains(root_mapping, guest_physical,
                                 address_bits)) {
        return MakeDmaResult(IommuLookupStatus::NotPresent, 0, 0,
                             root_mapping->generation);
    }
    if ((root_mapping->flags & kIommuMappingHostOwned) != 0) {
        return MakeDmaResult(IommuLookupStatus::HostOwned, 0, 0,
                             root_mapping->generation);
    }
    if (!IsIommuDmaAccessAllowed(root_mapping->permissions, access)) {
        return MakeDmaResult(IommuLookupStatus::PermissionDenied, 0, 0,
                             root_mapping->generation);
    }
    const u64 root_offset = guest_physical - root_mapping->iova;
    u64 host_physical = 0;
    if (AddOverflow(root_mapping->host_physical, root_offset,
                    &host_physical) ||
        !IsPhysicalAddress(host_physical, address_bits)) {
        return MakeDmaResult(IommuLookupStatus::Invalid, 0, 0,
                             root_mapping->generation);
    }
    return MakeDmaResult(IommuLookupStatus::Hit,
                         l1_mapping->permissions & root_mapping->permissions,
                         host_physical, root_mapping->generation);
}

IommuAssignmentStatus PrepareIommuAssignment(
    const IommuCapabilities* capabilities,
    const IommuDeviceProfile* profile, const IommuDomain* domain,
    u64 owner_id, u64 generation, IommuAssignment* assignment) {
    if (assignment == nullptr) return IommuAssignmentStatus::InvalidParameter;
    *assignment = {};
    assignment->size = sizeof(*assignment);
    assignment->version = kIommuContractVersion;
    if (capabilities == nullptr || profile == nullptr || domain == nullptr ||
        owner_id == 0 || generation == 0) {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::InvalidParameter);
        return IommuAssignmentStatus::InvalidParameter;
    }
    if (!IsIommuCapabilitiesValid(capabilities) ||
        !IsIommuDeviceProfileValid(profile,
                                   capabilities->max_physical_address_bits)) {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::InvalidParameter);
        return IommuAssignmentStatus::InvalidParameter;
    }
    if (!IsIommuDomainValid(domain, capabilities->max_physical_address_bits)) {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::DomainInvalid);
        return IommuAssignmentStatus::DomainInvalid;
    }
    if (generation != capabilities->generation ||
        generation != profile->profile_generation ||
        generation != domain->generation) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::GenerationMismatch);
        return IommuAssignmentStatus::GenerationMismatch;
    }
    if (domain->owner_id != owner_id || domain->domain_id >
                                             capabilities->max_domains) {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::DomainInvalid);
        return IommuAssignmentStatus::DomainInvalid;
    }
    if (profile->dma_address_bits > capabilities->max_domain_address_bits ||
        ((profile->flags & kIommuDeviceMsix) != 0 &&
         profile->max_msix_vectors > capabilities->max_msix_vectors)) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::CapabilityMismatch);
        return IommuAssignmentStatus::CapabilityMismatch;
    }
    if ((profile->flags & kIommuDeviceHostOwned) != 0) {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::HostOwned);
        return IommuAssignmentStatus::HostOwned;
    }
    if ((profile->flags & kIommuDeviceSystemCritical) != 0 ||
        (profile->flags & kIommuDeviceDisplay) != 0) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::CriticalDevice);
        return IommuAssignmentStatus::CriticalDevice;
    }
    if ((profile->flags & kIommuDeviceIsolationComplete) == 0 ||
        profile->isolation_group == 0) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::IsolationIncomplete);
        return IommuAssignmentStatus::IsolationIncomplete;
    }
    if ((profile->flags & kIommuDeviceHasRmrr) != 0) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::IsolationIncomplete);
        return IommuAssignmentStatus::IsolationIncomplete;
    }
    const auto kind = static_cast<IommuDomainKind>(domain->kind);
    if (kind == IommuDomainKind::Host || kind == IommuDomainKind::Quarantine) {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::DomainInvalid);
        return IommuAssignmentStatus::DomainInvalid;
    }
    if ((profile->flags & kIommuDeviceResetReliable) == 0) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::ResetUnsupported);
        return IommuAssignmentStatus::ResetUnsupported;
    }
    const u64 required_caps =
        kIommuCapQueuedInvalidation | kIommuCapInterruptRemapping;
    if ((capabilities->feature_flags & required_caps) != required_caps ||
        (domain->flags & kIommuDomainInterruptRemap) == 0) {
        SetAssignmentStatus(assignment,
                            IommuAssignmentStatus::CapabilityMismatch);
        return IommuAssignmentStatus::CapabilityMismatch;
    }
    if (kind == IommuDomainKind::L1) {
        if ((profile->flags & kIommuDeviceAllowL1) == 0) {
            SetAssignmentStatus(assignment,
                                IommuAssignmentStatus::CapabilityMismatch);
            return IommuAssignmentStatus::CapabilityMismatch;
        }
    } else if (kind == IommuDomainKind::L2) {
        const u64 nested_caps = required_caps | kIommuCapNestedTranslation;
        if ((capabilities->feature_flags & nested_caps) != nested_caps ||
            (profile->flags & kIommuDeviceAllowL2) == 0 ||
            (domain->flags & kIommuDomainNested) == 0) {
            SetAssignmentStatus(assignment,
                                IommuAssignmentStatus::CapabilityMismatch);
            return IommuAssignmentStatus::CapabilityMismatch;
        }
        if ((profile->flags & kIommuDeviceAts) != 0 &&
            (capabilities->feature_flags & kIommuCapAts) == 0) {
            SetAssignmentStatus(assignment,
                                IommuAssignmentStatus::CapabilityMismatch);
            return IommuAssignmentStatus::CapabilityMismatch;
        }
        if ((profile->flags & kIommuDevicePri) != 0 &&
            (capabilities->feature_flags & kIommuCapPri) == 0) {
            SetAssignmentStatus(assignment,
                                IommuAssignmentStatus::CapabilityMismatch);
            return IommuAssignmentStatus::CapabilityMismatch;
        }
        if ((profile->flags & kIommuDevicePasid) != 0 &&
            (capabilities->feature_flags & kIommuCapPasid) == 0) {
            SetAssignmentStatus(assignment,
                                IommuAssignmentStatus::CapabilityMismatch);
            return IommuAssignmentStatus::CapabilityMismatch;
        }
    } else {
        SetAssignmentStatus(assignment, IommuAssignmentStatus::DomainInvalid);
        return IommuAssignmentStatus::DomainInvalid;
    }

    assignment->bdf = profile->bdf;
    assignment->reset_method = profile->reset_method;
    assignment->owner_id = owner_id;
    assignment->domain_id = domain->domain_id;
    assignment->generation = generation;
    assignment->state = static_cast<u32>(IommuDomainState::Prepared);
    assignment->status = static_cast<u32>(IommuAssignmentStatus::Success);
    assignment->flags = kind == IommuDomainKind::L2
                            ? kIommuAssignmentNested
                            : 0U;
    if ((domain->flags & kIommuDomainInterruptRemap) != 0) {
        assignment->flags |= kIommuAssignmentInterruptRemap;
    }
    return IommuAssignmentStatus::Success;
}

bool ActivateIommuAssignment(IommuAssignment* assignment, u64 generation,
                             u32 readiness) {
    if (!IsAssignmentValid(assignment) ||
        assignment->status !=
            static_cast<u32>(IommuAssignmentStatus::Success) ||
        assignment->state != static_cast<u32>(IommuDomainState::Prepared) ||
        assignment->generation != generation ||
        !IsReadinessValid(readiness, kIommuActivateReadyMask)) {
        return false;
    }
    assignment->state = static_cast<u32>(IommuDomainState::Active);
    return true;
}

bool BeginIommuDetach(IommuAssignment* assignment, u64 generation,
                      u32 readiness) {
    if (!IsAssignmentValid(assignment) ||
        assignment->status !=
            static_cast<u32>(IommuAssignmentStatus::Success) ||
        assignment->state != static_cast<u32>(IommuDomainState::Active) ||
        assignment->generation != generation ||
        !IsReadinessValid(readiness, kIommuDetachReadyMask)) {
        return false;
    }
    assignment->state = static_cast<u32>(IommuDomainState::Draining);
    return true;
}

bool CompleteIommuDetach(IommuAssignment* assignment, u64 generation,
                         u32 readiness) {
    if (!IsAssignmentValid(assignment) ||
        assignment->status !=
            static_cast<u32>(IommuAssignmentStatus::Success) ||
        assignment->state != static_cast<u32>(IommuDomainState::Draining) ||
        assignment->generation != generation ||
        !IsReadinessValid(readiness, kIommuCompleteDetachReadyMask)) {
        return false;
    }
    assignment->state = static_cast<u32>(IommuDomainState::Retired);
    return true;
}

bool IsIommuFaultRecordValid(const IommuFaultRecord* fault,
                             u32 address_bits) {
    if (fault == nullptr ||
        !IsVersionedSizeValid(fault->version, fault->size,
                              sizeof(IommuFaultRecord)) ||
        !IsIommuBdfValid(&fault->bdf) || !IsFaultReasonValid(fault->reason) ||
        !IsDmaAccessValid(fault->access) || fault->reserved != 0 ||
        fault->generation == 0 || fault->sequence == 0 ||
        !IsPhysicalAddress(fault->address, address_bits)) {
        return false;
    }
    return true;
}

bool QuarantineIommuAssignment(IommuAssignment* assignment,
                               const IommuFaultRecord* fault) {
    if (!IsAssignmentValid(assignment) || fault == nullptr ||
        !IsIommuFaultRecordValid(fault, kIommuMaxPhysicalAddressBits) ||
        assignment->state == static_cast<u32>(IommuDomainState::Retired) ||
        assignment->state == static_cast<u32>(IommuDomainState::Quarantined) ||
        !IsSameBdf(assignment->bdf, fault->bdf) ||
        assignment->generation != fault->generation ||
        assignment->fault_count == ~0ULL) {
        return false;
    }
    ++assignment->fault_count;
    assignment->flags |= kIommuAssignmentQuarantined;
    assignment->state = static_cast<u32>(IommuDomainState::Quarantined);
    assignment->status =
        static_cast<u32>(IommuAssignmentStatus::FaultQuarantined);
    return true;
}

}  // namespace knhv
