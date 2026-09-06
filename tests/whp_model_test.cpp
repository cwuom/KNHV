#include "test_support.h"

#include "knhv_whp.h"

namespace knhv_tests {
namespace {

knhv::WhpCapabilities MakeCapabilities() {
    knhv::WhpCapabilities capabilities = {};
    capabilities.size = sizeof(capabilities);
    capabilities.version = knhv::kWhpContractVersion;
    capabilities.feature_flags =
        knhv::kWhpCapPartition | knhv::kWhpCapLocalApic |
        knhv::kWhpCapXsave | knhv::kWhpCapDirtyPageTracking |
        knhv::kWhpCapVirtualPci | knhv::kWhpCapIommu |
        knhv::kWhpCapNestedVmx | knhv::kWhpCapReferenceTime |
        knhv::kWhpCapExtendedExits;
    capabilities.extended_exit_flags = knhv::kWhpKnownExtendedExitMask;
    capabilities.api_version = 1;
    capabilities.physical_address_bits = 48;
    capabilities.max_vcpus = 4;
    capabilities.processor_clock_hz = 2400000000ULL;
    capabilities.generation = 9;
    return capabilities;
}

knhv::WhpPartitionConfig MakeConfig() {
    knhv::WhpPartitionConfig config = {};
    config.size = sizeof(config);
    config.version = knhv::kWhpContractVersion;
    config.owner_id = 55;
    config.generation = 9;
    config.max_vcpus = 2;
    config.physical_address_bits = 48;
    config.flags = knhv::kWhpPartitionEnableNestedVmx |
                   knhv::kWhpPartitionEnableLocalApic |
                   knhv::kWhpPartitionEnableReferenceTime |
                   knhv::kWhpPartitionRequireIsolation;
    return config;
}

knhv::WhpMemoryMapping MakeMapping() {
    knhv::WhpMemoryMapping mapping = {};
    mapping.size = sizeof(mapping);
    mapping.version = knhv::kWhpContractVersion;
    mapping.guest_physical = 0x2000;
    mapping.host_address = 0x100000;
    mapping.page_count = 2;
    mapping.permissions = knhv::kWhpMappingRead | knhv::kWhpMappingWrite;
    mapping.flags = knhv::kWhpMappingPrivate;
    mapping.generation = 9;
    return mapping;
}

knhv::WhpExitRecord MakeExit(knhv::WhpExitReason reason) {
    knhv::WhpExitRecord record = {};
    record.size = sizeof(record);
    record.version = knhv::kWhpContractVersion;
    record.reason = static_cast<std::uint32_t>(reason);
    record.vcpu_index = 0;
    record.instruction_length = 2;
    record.guest_physical = 0x2000;
    record.generation = 9;
    return record;
}

void CheckWhpLifecycle(TestState& state) {
    const knhv::WhpCapabilities capabilities = MakeCapabilities();
    const knhv::WhpPartitionConfig config = MakeConfig();
    Check(state, "WHP capability and partition contracts validate",
          knhv::IsWhpCapabilitiesValid(&capabilities) &&
              knhv::IsWhpPartitionConfigValid(&config));
    knhv::WhpPartition partition = {};
    Check(state, "WHP model creates a generation-bound partition",
          knhv::CreateWhpPartition(&capabilities, &config, 77, &partition) ==
              knhv::WhpStatus::Success &&
              partition.state == static_cast<std::uint32_t>(
                                     knhv::WhpPartitionState::Created));
    Check(state, "WHP model configures a bounded vCPU count",
          knhv::ConfigureWhpPartition(&partition, 9, 2) ==
              knhv::WhpStatus::Success &&
              partition.state == static_cast<std::uint32_t>(
                                     knhv::WhpPartitionState::Configured));
    const knhv::WhpMemoryMapping mapping = MakeMapping();
    Check(state, "WHP model maps an aligned private GPA range",
          knhv::IsWhpMemoryMappingValid(&mapping, 48) &&
              knhv::MapWhpGpa(&partition, &mapping, 9, 48) ==
                  knhv::WhpStatus::Success &&
              partition.mapping_count == 1 && partition.mapped_pages == 2);

    knhv::WhpVcpu vcpu = {};
    Check(state, "WHP model creates a vCPU only inside the configured range",
          knhv::CreateWhpVcpu(&partition, &vcpu, 0, 9) ==
              knhv::WhpStatus::Success && knhv::IsWhpVcpuValid(&vcpu));
    Check(state, "WHP model starts the partition before running a vCPU",
          knhv::StartWhpPartition(&partition, 9) &&
              knhv::StartWhpVcpu(&partition, &vcpu, 9) ==
                  knhv::WhpStatus::Success &&
              vcpu.state == static_cast<std::uint32_t>(
                                knhv::WhpVcpuState::Running));
    Check(state, "WHP model stops a vCPU and drains the partition",
          knhv::StopWhpVcpu(&partition, &vcpu, 9) ==
                  knhv::WhpStatus::Success &&
              knhv::BeginWhpDrain(&partition, 9) &&
              knhv::CloseWhpPartition(&partition, 9) &&
              partition.state == static_cast<std::uint32_t>(
                                     knhv::WhpPartitionState::Closed));
}

void CheckWhpExitPolicy(TestState& state) {
    const knhv::WhpCapabilities capabilities = MakeCapabilities();
    const knhv::WhpPartitionConfig config = MakeConfig();
    knhv::WhpPartition partition = {};
    knhv::CreateWhpPartition(&capabilities, &config, 77, &partition);
    knhv::ConfigureWhpPartition(&partition, 9, 1);
    knhv::StartWhpPartition(&partition, 9);
    const knhv::WhpExitRecord cpuid = MakeExit(knhv::WhpExitReason::Cpuid);
    knhv::WhpExitDecision decision = {};
    Check(state, "WHP exit policy routes CPUID to the CPU handler",
          knhv::EvaluateWhpExit(&partition, &cpuid, 9, &decision) &&
              decision.status ==
                  static_cast<std::uint32_t>(knhv::WhpStatus::Success) &&
              decision.action == static_cast<std::uint32_t>(
                                     knhv::WhpExitAction::HandleCpu));
    knhv::WhpExitRecord memory = MakeExit(
        knhv::WhpExitReason::MemoryAccess);
    Check(state, "WHP exit policy routes memory exits to the GPA handler",
          knhv::EvaluateWhpExit(&partition, &memory, 9, &decision) &&
              decision.action == static_cast<std::uint32_t>(
                                     knhv::WhpExitAction::HandleMemory));
    memory.generation = 10;
    Check(state, "WHP exit policy quarantines stale generations",
          knhv::EvaluateWhpExit(&partition, &memory, 9, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                     knhv::WhpStatus::GenerationMismatch) &&
              decision.action == static_cast<std::uint32_t>(
                                     knhv::WhpExitAction::Quarantine));
    knhv::WhpExitRecord unknown = MakeExit(
        static_cast<knhv::WhpExitReason>(0x7FFFFFFFU));
    Check(state, "WHP exit policy rejects an unknown exit reason",
          !knhv::EvaluateWhpExit(&partition, &unknown, 9, &decision));
}

void CheckWhpFailures(TestState& state) {
    knhv::WhpCapabilities capabilities = MakeCapabilities();
    knhv::WhpPartitionConfig config = MakeConfig();
    capabilities.feature_flags &= ~knhv::kWhpCapNestedVmx;
    knhv::WhpPartition partition = {};
    Check(state, "WHP model rejects nested configuration without capability",
          knhv::CreateWhpPartition(&capabilities, &config, 77, &partition) ==
              knhv::WhpStatus::CapabilityMismatch);
    capabilities = MakeCapabilities();
    config = MakeConfig();
    knhv::WhpMemoryMapping mapping = MakeMapping();
    mapping.guest_physical = 1ULL << 48;
    Check(state, "WHP mapping rejects a GPA outside the negotiated width",
          !knhv::IsWhpMemoryMappingValid(&mapping, 48));
    knhv::CreateWhpPartition(&capabilities, &config, 77, &partition);
    Check(state, "WHP model rejects a stale partition generation",
          knhv::ConfigureWhpPartition(&partition, 10, 1) ==
              knhv::WhpStatus::StateConflict);
    Check(state, "WHP quarantine prevents a closed partition from reopening",
          knhv::ConfigureWhpPartition(&partition, 9, 1) ==
                  knhv::WhpStatus::Success &&
              knhv::QuarantineWhpPartition(&partition, 9) &&
              !knhv::CloseWhpPartition(&partition, 9));
}

}  // namespace

void RunWhpModelContract(TestState& state) {
    CheckWhpLifecycle(state);
    CheckWhpExitPolicy(state);
    CheckWhpFailures(state);
}

}  // namespace knhv_tests
