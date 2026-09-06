#include "test_support.h"

#include "knhv_ept.h"
#include "knhv_time.h"

namespace knhv_tests {
namespace {

knhv::EptpConfig MakeEptp() {
    knhv::EptpConfig config = {};
    config.size = sizeof(config);
    config.version = knhv::kEptContractVersion;
    config.root_physical = 0x1000;
    config.memory_type = knhv::kEptMemoryTypeWb;
    config.walk_length = 4;
    config.flags = knhv::kEptpFlagAccessDirty;
    config.generation = 1;
    return config;
}

knhv::EptMapping MakeMapping(std::uint64_t guest, std::uint64_t host,
                             std::uint64_t pages, std::uint32_t order,
                             std::uint32_t permissions) {
    knhv::EptMapping mapping = {};
    mapping.size = sizeof(mapping);
    mapping.version = knhv::kEptContractVersion;
    mapping.guest_physical = guest;
    mapping.host_physical = host;
    mapping.page_count = pages;
    mapping.page_order = order;
    mapping.permissions = permissions;
    mapping.memory_type = knhv::kEptMemoryTypeWb;
    mapping.flags = knhv::kEptMappingFlagPresent;
    if (order != 0) mapping.flags |= knhv::kEptMappingFlagLargePage;
    mapping.generation = 1;
    return mapping;
}

knhv::TscTransform MakeTransform(std::uint64_t generation = 1) {
    knhv::TscTransform transform = {};
    transform.size = sizeof(transform);
    transform.version = knhv::kTimeContractVersion;
    transform.base_tsc = 0;
    transform.base_virtual_tsc = 0;
    transform.scale_q32_32 = knhv::kTimeScaleOneQ32_32;
    transform.generation = generation;
    transform.max_drift_ticks = 10;
    transform.flags = knhv::kTimeFlagMonotonicClamp;
    return transform;
}

void CheckEptPointerContract(TestState& state) {
    knhv::EptpConfig config = MakeEptp();
    Check(state, "EPTP accepts a four-level WB root",
          knhv::IsEptpConfigValid(&config, 48));
    std::uint64_t raw = 0;
    Check(state, "EPTP encoding preserves the access-dirty policy",
          knhv::BuildEptPointer(&config, &raw) && (raw & (1ULL << 6)) != 0);
    knhv::EptpConfig decoded = {};
    Check(state, "EPTP decoding preserves root and walk length",
          knhv::DecodeEptPointer(raw, &decoded) &&
              decoded.root_physical == config.root_physical &&
              decoded.walk_length == config.walk_length &&
              decoded.memory_type == config.memory_type);
    decoded.generation = 1;
    Check(state, "decoded EPTP can be promoted only with a generation",
          knhv::IsEptpConfigValid(&decoded, 48));
    Check(state, "EPTP rejects reserved high bits",
          !knhv::DecodeEptPointer(raw | (1ULL << 63), &decoded));
    config.walk_length = 3;
    Check(state, "EPTP rejects a short page walk",
          !knhv::IsEptpConfigValid(&config, 48));
}

void CheckEptMappingContract(TestState& state) {
    const std::uint32_t rwx = knhv::kEptPermissionRead |
                               knhv::kEptPermissionWrite |
                               knhv::kEptPermissionExecute;
    const knhv::EptMapping l1 = MakeMapping(0x0000, 0x2000, 4, 0, rwx);
    const knhv::EptMapping root = MakeMapping(0x2000, 0x8000, 4, 0, rwx);
    const knhv::EptLookupResult hit =
        knhv::ResolveNestedEpt(&l1, &root, 0x1234, knhv::EptAccess::Read);
    Check(state, "4K EPT mappings validate aligned ranges",
          knhv::IsEptMappingValid(&l1, 48) &&
              knhv::IsEptMappingValid(&root, 48));
    Check(state, "nested EPT resolves GPA through both mappings",
          hit.status == static_cast<std::uint32_t>(knhv::EptLookupStatus::Hit) &&
              hit.host_physical == 0x9234);
    const knhv::EptLookupResult execute =
        knhv::ResolveNestedEpt(&l1, &root, 0x1000, knhv::EptAccess::Execute);
    Check(state, "nested EPT intersects permissions",
          execute.permissions == knhv::kEptPermissionKnownMask);
    knhv::EptMapping no_write = root;
    no_write.permissions = knhv::kEptPermissionRead;
    Check(state, "nested EPT denies a missing root permission",
          knhv::ResolveNestedEpt(&l1, &no_write, 0x1000,
                                 knhv::EptAccess::Write)
                  .status == static_cast<std::uint32_t>(
                  knhv::EptLookupStatus::PermissionDenied));
    knhv::EptMapping stale = root;
    stale.generation = 2;
    Check(state, "nested EPT rejects mismatched generations",
          knhv::ResolveNestedEpt(&l1, &stale, 0x1000, knhv::EptAccess::Read)
                  .status == static_cast<std::uint32_t>(
                  knhv::EptLookupStatus::Stale));
    knhv::EptMapping host_owned = root;
    host_owned.flags |= knhv::kEptMappingFlagHostOwned;
    Check(state, "nested EPT refuses host-owned pages",
          knhv::ResolveNestedEpt(&l1, &host_owned, 0x1000,
                                 knhv::EptAccess::Read)
                  .status == static_cast<std::uint32_t>(
                  knhv::EptLookupStatus::HostOwned));
    knhv::EptMapping large = MakeMapping(0x200000, 0x400000, 1, 1, rwx);
    Check(state, "large EPT mappings require large-page alignment",
          knhv::IsEptMappingValid(&large, 48));
    large.host_physical += 0x1000;
    Check(state, "large EPT mappings reject misaligned roots",
          !knhv::IsEptMappingValid(&large, 48));
}

void CheckEptHookContract(TestState& state) {
    knhv::EptHookLease lease = {};
    lease.size = sizeof(lease);
    lease.version = knhv::kEptContractVersion;
    lease.owner_id = 7;
    lease.generation = 4;
    lease.expires_tsc = 1000;
    lease.view = static_cast<std::uint32_t>(knhv::EptViewKind::GuestDebug);
    lease.hook_kind = static_cast<std::uint32_t>(knhv::EptHookKind::Execute);
    lease.state = static_cast<std::uint32_t>(knhv::EptHookState::Active);
    lease.max_pages = 4;
    lease.max_exits_per_second = 100;
    knhv::EptHookRequest request = {};
    request.size = sizeof(request);
    request.version = knhv::kEptContractVersion;
    request.owner_id = lease.owner_id;
    request.expected_generation = lease.generation;
    request.guest_physical = 0x4000;
    request.page_count = 2;
    request.view = lease.view;
    request.hook_kind = lease.hook_kind;
    request.permissions = knhv::kEptPermissionExecute;
    request.module_hash[0] = 0x1234;
    Check(state, "EPT debug lease and signed-range request validate",
          knhv::IsEptHookLeaseValid(&lease) &&
              knhv::IsEptHookRequestValid(&request));
    Check(state, "EPT hook publication requires the live generation",
          knhv::CanPublishEptHook(&lease, &request, 4, 999));
    Check(state, "expired EPT hook leases are rejected",
          !knhv::CanPublishEptHook(&lease, &request, 4, 1000));
    request.page_count = 5;
    Check(state, "EPT hook range is bounded by the lease",
          !knhv::CanPublishEptHook(&lease, &request, 4, 999));
    request.page_count = 2;
    request.expected_generation = 3;
    Check(state, "stale EPT hook requests are rejected",
          !knhv::CanPublishEptHook(&lease, &request, 4, 999));
    request.expected_generation = 4;
    lease.view = static_cast<std::uint32_t>(knhv::EptViewKind::RootNative);
    Check(state, "root-native EPT views cannot receive hooks",
          !knhv::IsEptHookLeaseValid(&lease));
}

void CheckEptHookTransactionContract(TestState& state) {
    knhv::EptHookLease lease = {};
    lease.size = sizeof(lease);
    lease.version = knhv::kEptContractVersion;
    lease.owner_id = 7;
    lease.generation = 4;
    lease.expires_tsc = 1000;
    lease.view = static_cast<std::uint32_t>(knhv::EptViewKind::GuestDebug);
    lease.hook_kind = static_cast<std::uint32_t>(knhv::EptHookKind::Execute);
    lease.state = static_cast<std::uint32_t>(knhv::EptHookState::Active);
    lease.max_pages = 4;
    lease.max_exits_per_second = 100;

    knhv::EptHookRequest request = {};
    request.size = sizeof(request);
    request.version = knhv::kEptContractVersion;
    request.owner_id = lease.owner_id;
    request.expected_generation = lease.generation;
    request.guest_physical = 0x4000;
    request.page_count = 2;
    request.view = lease.view;
    request.hook_kind = lease.hook_kind;
    request.permissions = knhv::kEptPermissionExecute;
    request.module_hash[0] = 0x1234;

    knhv::EptHookTransaction transaction = {};
    Check(state, "EPT hook transaction creates a pending generation",
          knhv::BeginEptHookUpdate(&lease, &request, 4, 999, 2, 77,
                                   &transaction) &&
              transaction.pending_generation == 5 &&
              transaction.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::Prepared));
    Check(state, "EPT hook transaction rejects a stale CPU acknowledgement",
          !knhv::AcknowledgeEptHookCpu(&transaction, 3, 1, 999));
    Check(state, "EPT hook transaction accepts bounded CPU acknowledgements",
          knhv::AcknowledgeEptHookCpu(&transaction, 4, 1, 999) &&
              !knhv::PublishEptHookUpdate(&transaction, 4, 999));
    Check(state, "EPT hook transaction publishes after all acknowledgements",
          knhv::AcknowledgeEptHookCpu(&transaction, 4, 1, 999) &&
              knhv::PublishEptHookUpdate(&transaction, 4, 999) &&
              transaction.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::Published));
    knhv::EptHookMetadata metadata = {};
    metadata.size = sizeof(metadata);
    metadata.version = knhv::kEptContractVersion;
    metadata.original_page_physical = 0x100000;
    metadata.shadow_page_physical = 0x200000;
    metadata.module_hash[0] = request.module_hash[0];
    metadata.target_rip = 0x140000000ULL;
    metadata.instruction_length = 5;
    metadata.cet_policy = knhv::kEptHookCodeCet | knhv::kEptHookCodeIbt;
    metadata.cfg_policy = knhv::kEptHookCodeCfg;
    metadata.rollback_generation = 4;
    Check(state, "EPT hook metadata records code and rollback identity",
          knhv::IsEptHookMetadataValid(&metadata) &&
              knhv::IsEptHookMetadataCompatible(&request, &transaction,
                                                 &metadata));
    Check(state, "EPT hook transaction retires only on the new generation",
          !knhv::RetireEptHookUpdate(&transaction, 4) &&
              knhv::RetireEptHookUpdate(&transaction, 5) &&
              transaction.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::Retired));
    metadata.cet_policy = 1U << 12;
    Check(state, "EPT hook metadata rejects unknown code policy bits",
          !knhv::IsEptHookMetadataValid(&metadata));

    knhv::EptHookTransaction rollback = {};
    Check(state, "EPT hook transaction can roll back a prepared update",
          knhv::BeginEptHookUpdate(&lease, &request, 4, 999, 1, 78,
                                   &rollback) &&
              knhv::RollbackEptHookUpdate(&rollback, 4) &&
              rollback.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::RolledBack));
    knhv::EptHookTransaction quarantine = {};
    Check(state, "EPT hook transaction quarantines an unsafe update",
          knhv::BeginEptHookUpdate(&lease, &request, 4, 999, 1, 79,
                                   &quarantine) &&
              knhv::QuarantineEptHookUpdate(&quarantine, 4) &&
              quarantine.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::Quarantined));
    knhv::EptHookTransaction expired = {};
    Check(state, "expired prepared hook updates roll back automatically",
          knhv::BeginEptHookUpdate(&lease, &request, 4, 999, 1, 80,
                                   &expired) &&
              !knhv::IsEptHookTransactionLive(&expired, 1000) &&
              knhv::ExpireEptHookUpdate(&expired, 4, 1000) &&
              expired.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::RolledBack));
    knhv::EptHookTransaction expired_published = {};
    Check(state, "expired published hook updates enter quarantine",
          knhv::BeginEptHookUpdate(&lease, &request, 4, 999, 1, 81,
                                   &expired_published) &&
              knhv::AcknowledgeEptHookCpu(&expired_published, 4, 1, 999) &&
              knhv::PublishEptHookUpdate(&expired_published, 4, 999) &&
              knhv::ExpireEptHookUpdate(&expired_published, 5, 1000) &&
              expired_published.state == static_cast<std::uint32_t>(
                  knhv::EptHookTransactionState::Quarantined));
    Check(state, "EPT hook rate budget uses a bounded TSC window",
          knhv::IsEptHookRateWithin(&lease, 50, 500, 1000) &&
              !knhv::IsEptHookRateWithin(&lease, 51, 500, 1000) &&
              knhv::IsEptHookRateWithin(&lease, 100, 1000, 1000));
    Check(state, "EPT hook rate budget rejects arithmetic overflow",
          !knhv::IsEptHookRateWithin(&lease, ~0ULL, 1, ~0ULL));

    request.guest_physical = 0x000FFFFFFFFFF000ULL;
    request.page_count = 2;
    Check(state, "EPT hook ranges reject a physical address overflow",
          !knhv::IsEptHookRequestValid(&request));
}

void CheckEptGenerationContract(TestState& state) {
    knhv::EptGeneration current = {};
    current.size = sizeof(current);
    current.version = knhv::kEptContractVersion;
    current.generation = 9;
    current.state = static_cast<std::uint32_t>(knhv::EptGenerationState::Active);
    knhv::EptGeneration pending = {};
    Check(state, "EPT generation publish starts from an active parent",
          knhv::BeginEptGeneration(&current, &pending) &&
              pending.generation == 10 &&
              pending.state == static_cast<std::uint32_t>(
                  knhv::EptGenerationState::Pending));
    pending.required_cpu_acks = 2;
    Check(state, "EPT generation rejects acknowledgements beyond its CPU set",
          !knhv::AcknowledgeEptGeneration(&pending, 3));
    Check(state, "EPT generation waits for all CPU acknowledgements",
          knhv::AcknowledgeEptGeneration(&pending, 1) &&
              !knhv::PublishEptGeneration(&pending));
    Check(state, "EPT generation publishes after the final acknowledgement",
          knhv::AcknowledgeEptGeneration(&pending, 1) &&
              knhv::PublishEptGeneration(&pending) &&
              pending.state == static_cast<std::uint32_t>(
                  knhv::EptGenerationState::Active));
    std::uint64_t next = 0;
    Check(state, "EPT generation detects counter exhaustion",
          !knhv::NextEptGeneration(~0ULL, &next));
}

void CheckTimeContract(TestState& state) {
    const knhv::TscQpcSample first = {1000, 2000};
    const knhv::TscQpcSample second = {5000, 6000};
    knhv::TscTransform calibrated = {};
    Check(state, "TSC calibration derives a fixed-point unit scale",
          knhv::CalibrateTscTransform(&first, &second, 3, 4, &calibrated) &&
              calibrated.scale_q32_32 == knhv::kTimeScaleOneQ32_32);
    std::uint64_t virtual_tsc = 0;
    Check(state, "TSC transform preserves the calibrated offset",
          knhv::ApplyTscTransform(&calibrated, 3000, &virtual_tsc) ==
              knhv::TimeResultCode::Success && virtual_tsc == 4000);
    knhv::TimeObservation observation = {};
    Check(state, "TSC/QPC observation accepts bounded drift",
          knhv::ObserveTimeSample(&calibrated, 3000, 4002, &observation) ==
              knhv::TimeResultCode::Success && observation.drift_ticks == -2);
    Check(state, "TSC/QPC observation rejects excessive drift",
          knhv::ObserveTimeSample(&calibrated, 3000, 4010, &observation) ==
              knhv::TimeResultCode::DriftExceeded);
    calibrated.last_virtual_tsc = 5000;
    Check(state, "monotonic clamp prevents a backwards virtual TSC",
          knhv::ApplyTscTransform(&calibrated, 3000, &virtual_tsc) ==
              knhv::TimeResultCode::Success && virtual_tsc == 5000);
    calibrated.flags &= ~knhv::kTimeFlagMonotonicClamp;
    Check(state, "strict time mode reports a backwards virtual TSC",
          knhv::ApplyTscTransform(&calibrated, 3000, &virtual_tsc) ==
              knhv::TimeResultCode::NonMonotonic);
}

void CheckTimeCompositionContract(TestState& state) {
    knhv::TscTransform outer = MakeTransform(8);
    knhv::TscTransform inner = MakeTransform(8);
    inner.scale_q32_32 = 2ULL * knhv::kTimeScaleOneQ32_32;
    std::uint64_t value = 0;
    Check(state, "nested time transforms compose with one generation",
          knhv::ComposeTscTransforms(&outer, &inner, 100, &value) ==
              knhv::TimeResultCode::Success && value == 200);
    inner.generation = 9;
    Check(state, "nested time transforms reject stale generations",
          knhv::ComposeTscTransforms(&outer, &inner, 100, &value) ==
              knhv::TimeResultCode::GenerationMismatch);
    outer = MakeTransform(8);
    outer.last_virtual_tsc = 100;
    Check(state, "time rebase raises a transform without a jump backwards",
          knhv::RebaseTscTransform(&outer, 20, 200) &&
              knhv::ApplyTscTransform(&outer, 20, &value) ==
                  knhv::TimeResultCode::Success && value == 200);
    std::uint64_t next = 0;
    Check(state, "time generation detects counter exhaustion",
          !knhv::NextTimeGeneration(~0ULL, &next));
}

}  // namespace

void RunEptTimeModelContract(TestState& state) {
    CheckEptPointerContract(state);
    CheckEptMappingContract(state);
    CheckEptHookContract(state);
    CheckEptHookTransactionContract(state);
    CheckEptGenerationContract(state);
    CheckTimeContract(state);
    CheckTimeCompositionContract(state);
}

}  // namespace knhv_tests
