#include "knhv_whp.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kWhpContractVersion && size >= required &&
           size <= kWhpMaxStructSize;
}

bool IsAddressValid(u64 address, u32 bits) {
    return bits >= 12U && bits <= kWhpMaxPhysicalAddressBits &&
           (address >> bits) == 0;
}

bool AddOverflow(u64 left, u64 right, u64* result) {
    if (result == nullptr || left > ~0ULL - right) return true;
    *result = left + right;
    return false;
}

bool IsPartitionStateValidValue(u32 value) {
    return value <= static_cast<u32>(WhpPartitionState::Quarantined);
}

bool IsVcpuStateValidValue(u32 value) {
    return value <= static_cast<u32>(WhpVcpuState::Failed);
}

bool IsReasonValid(u32 value) {
    switch (static_cast<WhpExitReason>(value)) {
        case WhpExitReason::MemoryAccess:
        case WhpExitReason::IoPortAccess:
        case WhpExitReason::UnrecoverableException:
        case WhpExitReason::InvalidVpRegisterValue:
        case WhpExitReason::UnsupportedFeature:
        case WhpExitReason::InterruptWindow:
        case WhpExitReason::Halt:
        case WhpExitReason::ApicEoi:
        case WhpExitReason::MsrAccess:
        case WhpExitReason::Cpuid:
        case WhpExitReason::Exception:
        case WhpExitReason::Rdtsc:
        case WhpExitReason::Hypercall:
        case WhpExitReason::Canceled:
            return true;
        default:
            return false;
    }
}

void InitializePartition(WhpPartition* partition) {
    *partition = {};
    partition->size = sizeof(*partition);
    partition->version = kWhpContractVersion;
    partition->state = static_cast<u32>(WhpPartitionState::Empty);
}

void InitializeVcpu(WhpVcpu* vcpu) {
    *vcpu = {};
    vcpu->size = sizeof(*vcpu);
    vcpu->version = kWhpContractVersion;
    vcpu->state = static_cast<u32>(WhpVcpuState::Empty);
}

void InitializeDecision(const WhpExitRecord* record, WhpExitDecision* decision) {
    *decision = {};
    decision->size = sizeof(*decision);
    decision->version = kWhpContractVersion;
    decision->reason = record == nullptr ? 0U : record->reason;
    decision->generation = record == nullptr ? 0ULL : record->generation;
}

void SetDecision(WhpExitDecision* decision, WhpStatus status,
                 WhpExitAction action) {
    decision->status = static_cast<u32>(status);
    decision->action = static_cast<u32>(action);
}

}  // namespace

bool IsWhpCapabilitiesValid(const WhpCapabilities* capabilities) {
    return capabilities != nullptr &&
           IsVersionedSizeValid(capabilities->version, capabilities->size,
                                sizeof(WhpCapabilities)) &&
           (capabilities->feature_flags & ~kWhpKnownCapabilityMask) == 0 &&
           (capabilities->extended_exit_flags &
            ~kWhpKnownExtendedExitMask) == 0 &&
           capabilities->api_version != 0 &&
           capabilities->physical_address_bits >= 12U &&
           capabilities->physical_address_bits <= kWhpMaxPhysicalAddressBits &&
           capabilities->max_vcpus != 0 &&
           capabilities->max_vcpus <= kWhpMaxVcpus && capabilities->reserved == 0 &&
           capabilities->generation != 0;
}

bool IsWhpPartitionConfigValid(const WhpPartitionConfig* config) {
    return config != nullptr &&
           IsVersionedSizeValid(config->version, config->size,
                                sizeof(WhpPartitionConfig)) &&
           config->owner_id != 0 && config->generation != 0 &&
           config->max_vcpus != 0 && config->max_vcpus <= kWhpMaxVcpus &&
           config->physical_address_bits >= 12U &&
           config->physical_address_bits <= kWhpMaxPhysicalAddressBits &&
           (config->flags & ~kWhpKnownPartitionFlagMask) == 0 &&
           config->reserved == 0;
}

bool IsWhpPartitionValid(const WhpPartition* partition) {
    if (partition == nullptr ||
        !IsVersionedSizeValid(partition->version, partition->size,
                              sizeof(WhpPartition)) ||
        partition->partition_id == 0 || partition->owner_id == 0 ||
        partition->generation == 0 ||
        !IsPartitionStateValidValue(partition->state) ||
        (partition->flags & ~kWhpKnownPartitionFlagMask) != 0 ||
        partition->max_vcpus == 0 || partition->max_vcpus > kWhpMaxVcpus ||
        partition->configured_vcpus > partition->max_vcpus ||
        partition->mapping_count > kWhpMaxMappings || partition->reserved != 0) {
        return false;
    }
    if (partition->state == static_cast<u32>(WhpPartitionState::Empty)) {
        return partition->configured_vcpus == 0 &&
               partition->mapping_count == 0 && partition->mapped_pages == 0;
    }
    return true;
}

bool IsWhpMemoryMappingValid(const WhpMemoryMapping* mapping,
                             u32 physical_address_bits) {
    if (mapping == nullptr ||
        !IsVersionedSizeValid(mapping->version, mapping->size,
                              sizeof(WhpMemoryMapping)) ||
        mapping->host_address == 0 || mapping->page_count == 0 ||
        mapping->page_count > (1ULL << 20) ||
        (mapping->permissions & ~kWhpKnownMappingPermissionMask) != 0 ||
        mapping->permissions == 0 ||
        (mapping->flags & ~kWhpKnownMappingFlagMask) != 0 ||
        mapping->generation == 0 ||
        (mapping->guest_physical & (kWhpPageSize - 1ULL)) != 0 ||
        (mapping->host_address & (kWhpPageSize - 1ULL)) != 0 ||
        !IsAddressValid(mapping->guest_physical, physical_address_bits)) {
        return false;
    }
    const u64 span = mapping->page_count * kWhpPageSize;
    u64 last = 0;
    if (AddOverflow(mapping->guest_physical, span - 1ULL, &last) ||
        !IsAddressValid(last, physical_address_bits) ||
        AddOverflow(mapping->host_address, span - 1ULL, &last)) {
        return false;
    }
    return true;
}

bool IsWhpVcpuValid(const WhpVcpu* vcpu) {
    if (vcpu == nullptr ||
        !IsVersionedSizeValid(vcpu->version, vcpu->size, sizeof(WhpVcpu)) ||
        !IsVcpuStateValidValue(vcpu->state) || vcpu->generation == 0) {
        return false;
    }
    if (vcpu->state == static_cast<u32>(WhpVcpuState::Empty)) {
        return vcpu->index == 0 && vcpu->run_count == 0 &&
               vcpu->exit_count == 0;
    }
    return vcpu->index < kWhpMaxVcpus;
}

bool IsWhpExitRecordValid(const WhpExitRecord* record) {
    return record != nullptr &&
           IsVersionedSizeValid(record->version, record->size,
                                sizeof(WhpExitRecord)) &&
           IsReasonValid(record->reason) && record->vcpu_index < kWhpMaxVcpus &&
           record->instruction_length <= 15U && record->reserved == 0 &&
           record->generation != 0 &&
           IsAddressValid(record->guest_physical,
                          kWhpMaxPhysicalAddressBits);
}

WhpStatus CreateWhpPartition(const WhpCapabilities* capabilities,
                             const WhpPartitionConfig* config,
                             u64 partition_id, WhpPartition* partition) {
    if (partition == nullptr) return WhpStatus::InvalidParameter;
    InitializePartition(partition);
    if (!IsWhpCapabilitiesValid(capabilities) ||
        !IsWhpPartitionConfigValid(config) || partition_id == 0 ||
        capabilities->generation != config->generation ||
        (capabilities->feature_flags & kWhpCapPartition) == 0 ||
        config->max_vcpus > capabilities->max_vcpus ||
        config->physical_address_bits > capabilities->physical_address_bits) {
        return WhpStatus::CapabilityMismatch;
    }
    if ((config->flags & kWhpPartitionEnableNestedVmx) != 0 &&
        (capabilities->feature_flags & kWhpCapNestedVmx) == 0) {
        return WhpStatus::CapabilityMismatch;
    }
    if ((config->flags & kWhpPartitionEnableLocalApic) != 0 &&
        (capabilities->feature_flags & kWhpCapLocalApic) == 0) {
        return WhpStatus::CapabilityMismatch;
    }
    if ((config->flags & kWhpPartitionEnableReferenceTime) != 0 &&
        (capabilities->feature_flags & kWhpCapReferenceTime) == 0) {
        return WhpStatus::CapabilityMismatch;
    }
    if ((config->flags & kWhpPartitionRequireIsolation) != 0 &&
        (capabilities->feature_flags & kWhpCapIommu) == 0) {
        return WhpStatus::CapabilityMismatch;
    }
    partition->partition_id = partition_id;
    partition->owner_id = config->owner_id;
    partition->generation = config->generation;
    partition->flags = config->flags;
    partition->max_vcpus = config->max_vcpus;
    partition->state = static_cast<u32>(WhpPartitionState::Created);
    return WhpStatus::Success;
}

WhpStatus ConfigureWhpPartition(WhpPartition* partition, u64 generation,
                                u32 vcpu_count) {
    if (!IsWhpPartitionValid(partition) || generation == 0 ||
        partition->generation != generation ||
        partition->state != static_cast<u32>(WhpPartitionState::Created) ||
        vcpu_count == 0 || vcpu_count > partition->max_vcpus) {
        return WhpStatus::StateConflict;
    }
    partition->configured_vcpus = vcpu_count;
    partition->state = static_cast<u32>(WhpPartitionState::Configured);
    return WhpStatus::Success;
}

WhpStatus MapWhpGpa(WhpPartition* partition,
                    const WhpMemoryMapping* mapping, u64 generation,
                    u32 physical_address_bits) {
    if (!IsWhpPartitionValid(partition) ||
        !IsWhpMemoryMappingValid(mapping, physical_address_bits)) {
        return WhpStatus::InvalidParameter;
    }
    if (partition->generation != generation || mapping->generation != generation) {
        return WhpStatus::GenerationMismatch;
    }
    if (partition->state != static_cast<u32>(WhpPartitionState::Created) &&
        partition->state != static_cast<u32>(WhpPartitionState::Configured)) {
        return WhpStatus::StateConflict;
    }
    if (partition->mapping_count >= kWhpMaxMappings ||
        partition->mapped_pages > ~0ULL - mapping->page_count) {
        return WhpStatus::LimitExceeded;
    }
    ++partition->mapping_count;
    partition->mapped_pages += mapping->page_count;
    return WhpStatus::Success;
}

WhpStatus CreateWhpVcpu(const WhpPartition* partition, WhpVcpu* vcpu,
                        u32 index, u64 generation) {
    if (vcpu == nullptr) return WhpStatus::InvalidParameter;
    InitializeVcpu(vcpu);
    if (!IsWhpPartitionValid(partition) || generation == 0 ||
        partition->generation != generation ||
        partition->state != static_cast<u32>(WhpPartitionState::Configured) ||
        index >= partition->configured_vcpus) {
        return WhpStatus::StateConflict;
    }
    vcpu->index = index;
    vcpu->generation = generation;
    vcpu->state = static_cast<u32>(WhpVcpuState::Created);
    return WhpStatus::Success;
}

WhpStatus StartWhpVcpu(WhpPartition* partition, WhpVcpu* vcpu,
                       u64 generation) {
    if (!IsWhpPartitionValid(partition) || !IsWhpVcpuValid(vcpu) ||
        generation == 0 || partition->generation != generation ||
        vcpu->generation != generation ||
        partition->state != static_cast<u32>(WhpPartitionState::Running) ||
        vcpu->index >= partition->configured_vcpus ||
        (vcpu->state != static_cast<u32>(WhpVcpuState::Created) &&
         vcpu->state != static_cast<u32>(WhpVcpuState::Stopped)) ||
        vcpu->run_count == ~0ULL) {
        return WhpStatus::StateConflict;
    }
    vcpu->state = static_cast<u32>(WhpVcpuState::Running);
    ++vcpu->run_count;
    return WhpStatus::Success;
}

WhpStatus StopWhpVcpu(WhpPartition* partition, WhpVcpu* vcpu,
                      u64 generation) {
    if (!IsWhpPartitionValid(partition) || !IsWhpVcpuValid(vcpu) ||
        generation == 0 || partition->generation != generation ||
        vcpu->generation != generation ||
        (partition->state != static_cast<u32>(WhpPartitionState::Running) &&
         partition->state != static_cast<u32>(WhpPartitionState::Draining)) ||
        vcpu->state != static_cast<u32>(WhpVcpuState::Running)) {
        return WhpStatus::StateConflict;
    }
    vcpu->state = static_cast<u32>(WhpVcpuState::Stopped);
    return WhpStatus::Success;
}

bool StartWhpPartition(WhpPartition* partition, u64 generation) {
    if (!IsWhpPartitionValid(partition) || generation == 0 ||
        partition->generation != generation ||
        partition->state != static_cast<u32>(WhpPartitionState::Configured) ||
        partition->configured_vcpus == 0) {
        return false;
    }
    partition->state = static_cast<u32>(WhpPartitionState::Running);
    return true;
}

bool BeginWhpDrain(WhpPartition* partition, u64 generation) {
    if (!IsWhpPartitionValid(partition) || generation == 0 ||
        partition->generation != generation ||
        (partition->state != static_cast<u32>(WhpPartitionState::Running) &&
         partition->state != static_cast<u32>(WhpPartitionState::Configured))) {
        return false;
    }
    partition->state = static_cast<u32>(WhpPartitionState::Draining);
    return true;
}

bool CloseWhpPartition(WhpPartition* partition, u64 generation) {
    if (!IsWhpPartitionValid(partition) || generation == 0 ||
        partition->generation != generation ||
        (partition->state != static_cast<u32>(WhpPartitionState::Created) &&
         partition->state != static_cast<u32>(WhpPartitionState::Configured) &&
         partition->state != static_cast<u32>(WhpPartitionState::Draining))) {
        return false;
    }
    partition->state = static_cast<u32>(WhpPartitionState::Closed);
    return true;
}

bool QuarantineWhpPartition(WhpPartition* partition, u64 generation) {
    if (!IsWhpPartitionValid(partition) || generation == 0 ||
        partition->generation != generation ||
        partition->state == static_cast<u32>(WhpPartitionState::Closed) ||
        partition->state == static_cast<u32>(WhpPartitionState::Quarantined)) {
        return false;
    }
    partition->state = static_cast<u32>(WhpPartitionState::Quarantined);
    return true;
}

bool EvaluateWhpExit(const WhpPartition* partition,
                     const WhpExitRecord* record, u64 generation,
                     WhpExitDecision* decision) {
    if (decision == nullptr) return false;
    InitializeDecision(record, decision);
    if (!IsWhpPartitionValid(partition) || !IsWhpExitRecordValid(record)) {
        SetDecision(decision, WhpStatus::InvalidParameter,
                    WhpExitAction::Quarantine);
        return false;
    }
    if (generation == 0 || partition->generation != generation ||
        record->generation != generation) {
        SetDecision(decision, WhpStatus::GenerationMismatch,
                    WhpExitAction::Quarantine);
        return true;
    }
    if (partition->state != static_cast<u32>(WhpPartitionState::Running) ||
        record->vcpu_index >= partition->configured_vcpus) {
        SetDecision(decision, WhpStatus::StateConflict,
                    WhpExitAction::Quarantine);
        return true;
    }
    switch (static_cast<WhpExitReason>(record->reason)) {
        case WhpExitReason::MemoryAccess:
            SetDecision(decision, WhpStatus::Success,
                        WhpExitAction::HandleMemory);
            break;
        case WhpExitReason::IoPortAccess:
            SetDecision(decision, WhpStatus::Success, WhpExitAction::HandleIo);
            break;
        case WhpExitReason::MsrAccess:
        case WhpExitReason::Cpuid:
        case WhpExitReason::Exception:
        case WhpExitReason::Rdtsc:
        case WhpExitReason::Hypercall:
        case WhpExitReason::InterruptWindow:
        case WhpExitReason::ApicEoi:
            SetDecision(decision, WhpStatus::Success, WhpExitAction::HandleCpu);
            break;
        case WhpExitReason::Halt:
        case WhpExitReason::Canceled:
            SetDecision(decision, WhpStatus::Success, WhpExitAction::Stop);
            break;
        default:
            SetDecision(decision, WhpStatus::ExitUnsupported,
                        WhpExitAction::Quarantine);
            break;
    }
    return true;
}

}  // namespace knhv
