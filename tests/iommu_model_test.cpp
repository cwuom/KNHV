#include "test_support.h"

#include "knhv_iommu.h"

namespace knhv_tests {
namespace {

knhv::IommuCapabilities MakeCapabilities() {
    knhv::IommuCapabilities capabilities = {};
    capabilities.size = sizeof(capabilities);
    capabilities.version = knhv::kIommuContractVersion;
    capabilities.feature_flags = knhv::kIommuCapQueuedInvalidation |
                                  knhv::kIommuCapInterruptRemapping |
                                  knhv::kIommuCapNestedTranslation |
                                  knhv::kIommuCapAts | knhv::kIommuCapPri |
                                  knhv::kIommuCapPasid;
    capabilities.max_physical_address_bits = 48;
    capabilities.max_domain_address_bits = 48;
    capabilities.max_domains = 64;
    capabilities.max_msix_vectors = 64;
    capabilities.max_reserved_ranges = knhv::kIommuMaxReservedRanges;
    capabilities.generation = 7;
    return capabilities;
}

knhv::IommuDeviceProfile MakeProfile() {
    knhv::IommuDeviceProfile profile = {};
    profile.size = sizeof(profile);
    profile.version = knhv::kIommuContractVersion;
    profile.bdf.bus = 2;
    profile.bdf.device = 3;
    profile.bdf.function = 1;
    profile.isolation_group = 9;
    profile.flags = knhv::kIommuDeviceIsolationComplete |
                    knhv::kIommuDeviceResetReliable |
                    knhv::kIommuDeviceAllowL1 |
                    knhv::kIommuDeviceAllowL2 | knhv::kIommuDeviceAts |
                    knhv::kIommuDevicePri | knhv::kIommuDevicePasid |
                    knhv::kIommuDeviceMsix;
    profile.reset_method =
        static_cast<std::uint32_t>(knhv::IommuResetMethod::Flr);
    profile.dma_address_bits = 48;
    profile.max_msix_vectors = 8;
    profile.profile_generation = 7;
    profile.dma_mask = (1ULL << 48) - 1ULL;
    return profile;
}

knhv::IommuDomain MakeDomain(knhv::IommuDomainKind kind) {
    knhv::IommuDomain domain = {};
    domain.size = sizeof(domain);
    domain.version = knhv::kIommuContractVersion;
    domain.domain_id = 4;
    domain.owner_id = 42;
    domain.parent_domain_id = kind == knhv::IommuDomainKind::L2 ? 1 : 0;
    domain.generation = 7;
    domain.kind = static_cast<std::uint32_t>(kind);
    domain.state = static_cast<std::uint32_t>(
        knhv::IommuDomainState::Prepared);
    domain.flags = knhv::kIommuDomainInterruptRemap;
    if (kind == knhv::IommuDomainKind::L2) {
        domain.flags |= knhv::kIommuDomainNested;
    }
    domain.address_bits = 48;
    domain.guest_base = 0;
    domain.guest_limit = 0xFFFFF;
    domain.mapped_pages = 16;
    return domain;
}

knhv::IommuDmaMapping MakeMapping(std::uint64_t iova,
                                  std::uint64_t guest,
                                  std::uint64_t host,
                                  std::uint64_t pages = 4) {
    knhv::IommuDmaMapping mapping = {};
    mapping.size = sizeof(mapping);
    mapping.version = knhv::kIommuContractVersion;
    mapping.iova = iova;
    mapping.guest_physical = guest;
    mapping.host_physical = host;
    mapping.page_count = pages;
    mapping.permissions = knhv::kIommuPermissionRead |
                          knhv::kIommuPermissionWrite;
    mapping.flags = knhv::kIommuMappingPresent |
                    knhv::kIommuMappingPinned;
    mapping.generation = 7;
    return mapping;
}

void CheckIommuContracts(TestState& state) {
    const knhv::IommuCapabilities capabilities = MakeCapabilities();
    const knhv::IommuDeviceProfile profile = MakeProfile();
    const knhv::IommuDomain l2 = MakeDomain(knhv::IommuDomainKind::L2);
    Check(state, "IOMMU capabilities, device profile, and L2 domain validate",
          knhv::IsIommuCapabilitiesValid(&capabilities) &&
              knhv::IsIommuDeviceProfileValid(
                  &profile, capabilities.max_physical_address_bits) &&
              knhv::IsIommuDomainValid(&l2,
                                       capabilities.max_physical_address_bits));
    knhv::IommuAssignment assignment = {};
    Check(state, "IOMMU L2 assignment requires nested translation gates",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &l2, 42, 7,
                                       &assignment) ==
              knhv::IommuAssignmentStatus::Success &&
              (assignment.flags & knhv::kIommuAssignmentNested) != 0 &&
              assignment.state == static_cast<std::uint32_t>(
                                      knhv::IommuDomainState::Prepared));
    Check(state, "IOMMU activation waits for quiesce, drain, and reset",
          !knhv::ActivateIommuAssignment(&assignment, 7,
                                         knhv::kIommuReadyHostQuiesced) &&
              knhv::ActivateIommuAssignment(
                  &assignment, 7, knhv::kIommuActivateReadyMask) &&
              assignment.state == static_cast<std::uint32_t>(
                                      knhv::IommuDomainState::Active));
    Check(state, "IOMMU detach cannot finish before reset completion",
          knhv::BeginIommuDetach(&assignment, 7, knhv::kIommuDetachReadyMask) &&
              !knhv::CompleteIommuDetach(&assignment, 7,
                                         knhv::kIommuDetachReadyMask) &&
              knhv::CompleteIommuDetach(
                  &assignment, 7, knhv::kIommuCompleteDetachReadyMask) &&
              assignment.state == static_cast<std::uint32_t>(
                                      knhv::IommuDomainState::Retired));
}

void CheckIommuAssignmentRejections(TestState& state) {
    knhv::IommuCapabilities capabilities = MakeCapabilities();
    knhv::IommuDeviceProfile profile = MakeProfile();
    knhv::IommuDomain domain = MakeDomain(knhv::IommuDomainKind::L2);
    knhv::IommuAssignment assignment = {};
    Check(state, "IOMMU rejects a stale capability generation",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       6, &assignment) ==
              knhv::IommuAssignmentStatus::GenerationMismatch);
    capabilities = MakeCapabilities();
    profile = MakeProfile();
    domain = MakeDomain(knhv::IommuDomainKind::L2);
    profile.flags |= knhv::kIommuDeviceHasRmrr;
    profile.rmrr_count = 1;
    profile.rmrr[0].base = 0x100000;
    profile.rmrr[0].length = 0x1000;
    Check(state, "IOMMU rejects an L2 device with RMRR",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::IsolationIncomplete);
    profile = MakeProfile();
    profile.flags |= knhv::kIommuDeviceHostOwned;
    Check(state, "IOMMU refuses a host-owned device",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::HostOwned);
    profile = MakeProfile();
    profile.flags &= ~knhv::kIommuDeviceResetReliable;
    profile.reset_method =
        static_cast<std::uint32_t>(knhv::IommuResetMethod::None);
    Check(state, "IOMMU refuses a device without a reliable reset",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::ResetUnsupported);
    profile = MakeProfile();
    capabilities.feature_flags &= ~knhv::kIommuCapNestedTranslation;
    Check(state, "IOMMU refuses L2 when nested translation is absent",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::CapabilityMismatch);
    profile = MakeProfile();
    capabilities = MakeCapabilities();
    domain = MakeDomain(knhv::IommuDomainKind::L1);
    Check(state, "IOMMU permits only explicitly profiled L1 assignment",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::Success &&
              (assignment.flags & knhv::kIommuAssignmentNested) == 0);
    domain = MakeDomain(knhv::IommuDomainKind::L2);
    domain.owner_id = 99;
    Check(state, "IOMMU binds assignment to the domain owner",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::DomainInvalid);
}

void CheckIommuDmaTranslation(TestState& state) {
    const knhv::IommuDmaMapping l1 = MakeMapping(0x1000, 0x9000, 0, 4);
    const knhv::IommuDmaMapping root = MakeMapping(0x9000, 0, 0x20000, 8);
    Check(state, "IOMMU mappings require pinned pages and aligned ranges",
          knhv::IsIommuDmaMappingValid(&l1, 48) &&
              knhv::IsIommuDmaMappingValid(&root, 48));
    const knhv::IommuDmaResult hit = knhv::ResolveNestedDma(
        &l1, &root, 0x1ABC, knhv::IommuDmaAccess::Write, 48);
    Check(state, "nested DMA translation resolves IOVA to HPA",
          hit.status == static_cast<std::uint32_t>(
                            knhv::IommuLookupStatus::Hit) &&
              hit.host_physical == 0x20ABC);
    knhv::IommuDmaMapping read_only = root;
    read_only.permissions = knhv::kIommuPermissionRead;
    Check(state, "nested DMA translation intersects write permissions",
          knhv::ResolveNestedDma(&l1, &read_only, 0x1ABC,
                                 knhv::IommuDmaAccess::Write, 48)
                  .status == static_cast<std::uint32_t>(
                  knhv::IommuLookupStatus::PermissionDenied));
    knhv::IommuDmaMapping stale = root;
    stale.generation = 8;
    Check(state, "nested DMA translation rejects stale mappings",
          knhv::ResolveNestedDma(&l1, &stale, 0x1ABC,
                                 knhv::IommuDmaAccess::Read, 48)
                  .status == static_cast<std::uint32_t>(
                  knhv::IommuLookupStatus::Stale));
    knhv::IommuDmaMapping host_owned = root;
    host_owned.flags |= knhv::kIommuMappingHostOwned;
    Check(state, "nested DMA translation refuses host-owned memory",
          knhv::ResolveNestedDma(&l1, &host_owned, 0x1ABC,
                                 knhv::IommuDmaAccess::Read, 48)
                  .status == static_cast<std::uint32_t>(
                  knhv::IommuLookupStatus::HostOwned));
    knhv::IommuDmaMapping unpinned = l1;
    unpinned.flags &= ~knhv::kIommuMappingPinned;
    Check(state, "IOMMU rejects unpinned DMA mappings",
          !knhv::IsIommuDmaMappingValid(&unpinned, 48));
    Check(state, "nested DMA translation reports an unmapped IOVA",
          knhv::ResolveNestedDma(&l1, &root, 0x9000,
                                 knhv::IommuDmaAccess::Read, 48)
                  .status == static_cast<std::uint32_t>(
                  knhv::IommuLookupStatus::NotPresent));
}

void CheckIommuFaultQuarantine(TestState& state) {
    knhv::IommuCapabilities capabilities = MakeCapabilities();
    knhv::IommuDeviceProfile profile = MakeProfile();
    knhv::IommuDomain domain = MakeDomain(knhv::IommuDomainKind::L2);
    knhv::IommuAssignment assignment = {};
    Check(state, "IOMMU assignment prepares for fault handling",
          knhv::PrepareIommuAssignment(&capabilities, &profile, &domain, 42,
                                       7, &assignment) ==
              knhv::IommuAssignmentStatus::Success);
    knhv::IommuFaultRecord fault = {};
    fault.size = sizeof(fault);
    fault.version = knhv::kIommuContractVersion;
    fault.reason = static_cast<std::uint32_t>(
        knhv::IommuFaultReason::Permission);
    fault.access = static_cast<std::uint32_t>(knhv::IommuDmaAccess::Write);
    fault.bdf = profile.bdf;
    fault.address = 0x123000;
    fault.generation = 7;
    fault.sequence = 1;
    Check(state, "IOMMU fault records are validated and quarantine the device",
          knhv::IsIommuFaultRecordValid(&fault, 48) &&
              knhv::QuarantineIommuAssignment(&assignment, &fault) &&
              assignment.state == static_cast<std::uint32_t>(
                                      knhv::IommuDomainState::Quarantined) &&
              assignment.status == static_cast<std::uint32_t>(
                                        knhv::IommuAssignmentStatus::FaultQuarantined) &&
              assignment.fault_count == 1);
    fault.sequence = 2;
    Check(state, "IOMMU rejects a second fault after quarantine transition",
          !knhv::QuarantineIommuAssignment(&assignment, &fault));
    fault.bdf.function = 7;
    Check(state, "IOMMU rejects a fault for a different BDF",
          !knhv::QuarantineIommuAssignment(&assignment, &fault));
}

}  // namespace

void RunIommuModelContract(TestState& state) {
    CheckIommuContracts(state);
    CheckIommuAssignmentRejections(state);
    CheckIommuDmaTranslation(state);
    CheckIommuFaultQuarantine(state);
}

}  // namespace knhv_tests
