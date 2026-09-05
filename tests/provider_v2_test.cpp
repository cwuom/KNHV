#include "test_support.h"

#include "knhv_provider.h"

namespace knhv_tests {
namespace {

knhv::HvProviderRequestV2 Request(knhv::HvLeaseModeV2 mode) {
    knhv::HvProviderRequestV2 request = {};
    request.size = sizeof(request);
    request.version = knhv::kAbiV2Version;
    request.request_id = 0x5632524551554553ULL;
    request.session.client_id = 41U;
    request.session.generation = 7U;
    request.mode = static_cast<knhv::u32>(mode);
    return request;
}

knhv::HvCapabilitySnapshot BootCapabilities() {
    knhv::HvCapabilitySnapshot capabilities =
        knhv::MakeFallbackCapabilitySnapshot(false, false);
    capabilities.feature_bits |= knhv::kCapEpt | knhv::kCapVpid |
                                 knhv::kCapBootL0 | knhv::kCapNestedVmx;
    capabilities.status_flags |= knhv::kFlagNativeVmxReady |
                                 knhv::kFlagBootHandoffVerified |
                                 knhv::kFlagKnhvBootL0Active;
    capabilities.owner_generation = 7U;
    capabilities.boot_generation = 6U;
    return capabilities;
}

void CheckV2Shape(TestState& state) {
    knhv::HvCapabilitySnapshot base = BootCapabilities();
    const knhv::HvCapabilitySnapshotV2 snapshot =
        knhv::MakeCapabilitySnapshotV2(&base);
    Check(state, "v2 capability snapshot has a bounded versioned shape",
          snapshot.version == knhv::kAbiV2Version &&
              snapshot.size == sizeof(snapshot) &&
              knhv::IsCapabilitySnapshotV2Valid(&snapshot));

    knhv::HvCapabilitySnapshotV2 future = snapshot;
    future.version = knhv::kAbiV2Version + 1U;
    Check(state, "v2 rejects a future capability version",
          !knhv::IsCapabilitySnapshotV2Valid(&future));

    knhv::HvCapabilitySnapshotV2 truncated = snapshot;
    truncated.size = sizeof(truncated) - 1U;
    Check(state, "v2 rejects a truncated capability buffer",
          !knhv::IsCapabilitySnapshotV2Valid(&truncated));

    knhv::HvCapabilitySnapshotV2 unknown = snapshot;
    unknown.policy_features |= 1ULL << 63;
    Check(state, "v2 rejects unknown policy bits",
          !knhv::IsCapabilitySnapshotV2Valid(&unknown));
}

void CheckProviderModes(TestState& state) {
    const knhv::HvCapabilitySnapshot boot = BootCapabilities();
    const knhv::HvCapabilitySnapshotV2 boot_v2 =
        knhv::MakeCapabilitySnapshotV2(&boot);
    knhv::HvProviderRequestV2 hardware = Request(
        knhv::HvLeaseModeV2::HardwareL0);
    hardware.flags = knhv::kRequestFlagRequireExclusive;
    hardware.required_hardware_features = knhv::kCapVmx | knhv::kCapEpt;
    knhv::HvProviderResponseV2 response = {};
    Check(state, "v2 grants hardware lease only to the KNHV owner",
          knhv::SelectProviderV2(&hardware, &boot_v2, &response) ==
              knhv::HvStatus::Success &&
              response.provider == knhv::HvProviderKind::BootL0Interposer &&
              response.lease.mode ==
                  static_cast<knhv::u32>(knhv::HvLeaseModeV2::HardwareL0) &&
              knhv::LeaseMatchesCapabilityV2(&response.lease, &boot_v2));

    knhv::HvCapabilitySnapshot external = boot;
    external.status_flags &= ~(knhv::kFlagKnhvBootL0Active |
                               knhv::kFlagBootHandoffVerified);
    external.status_flags |= knhv::kFlagOuterL0Active;
    const knhv::HvCapabilitySnapshotV2 external_v2 =
        knhv::MakeCapabilitySnapshotV2(&external);
    Check(state, "v2 rejects a competing external L0 owner",
          knhv::SelectProviderV2(&hardware, &external_v2, &response) ==
              knhv::HvStatus::HardwareOwnerConflict);

    knhv::HvCapabilitySnapshot contradictory = boot;
    contradictory.status_flags |= knhv::kFlagSyntheticSnapshot;
    const knhv::HvCapabilitySnapshotV2 contradictory_v2 =
        knhv::MakeCapabilitySnapshotV2(&contradictory);
    Check(state, "v2 rejects contradictory owner flags",
              contradictory_v2.state == static_cast<knhv::u32>(
                                      knhv::HvProviderStateV2::Conflict) &&
              knhv::SelectProviderV2(&hardware, &contradictory_v2, &response) ==
                  knhv::HvStatus::HardwareOwnerConflict);

    knhv::HvCapabilitySnapshot synthetic = boot;
    synthetic.status_flags &= ~(knhv::kFlagKnhvBootL0Active |
                                knhv::kFlagBootHandoffVerified |
                                knhv::kFlagNativeVmxReady);
    synthetic.status_flags |= knhv::kFlagSyntheticSnapshot |
                              knhv::kFlagNestedVmx;
    const knhv::HvCapabilitySnapshotV2 synthetic_v2 =
        knhv::MakeCapabilitySnapshotV2(&synthetic);
    knhv::HvProviderRequestV2 lab = Request(knhv::HvLeaseModeV2::SyntheticLab);
    lab.required_provider_features = knhv::kCapNestedVmx;
    lab.flags = knhv::kRequestFlagReadOnly;
    Check(state, "v2 marks the software lease as synthetic",
          knhv::SelectProviderV2(&lab, &synthetic_v2, &response) ==
              knhv::HvStatus::Success &&
              (response.lease.flags & knhv::kLeaseFlagSynthetic) != 0 &&
              !knhv::LeaseMatchesCapabilityV2(&response.lease, &boot_v2));
}

void CheckProviderFuzzEdges(TestState& state) {
    const knhv::HvCapabilitySnapshot base = BootCapabilities();
    const knhv::HvCapabilitySnapshotV2 capabilities =
        knhv::MakeCapabilitySnapshotV2(&base);
    knhv::HvProviderRequestV2 request =
        Request(knhv::HvLeaseModeV2::HardwareL0);
    knhv::HvProviderResponseV2 response = {};
    request.version = knhv::kAbiV2Version + 1U;
    Check(state, "v2 rejects a future request version",
          knhv::SelectProviderV2(&request, &capabilities, &response) ==
              knhv::HvStatus::InvalidParameter);
    request = Request(knhv::HvLeaseModeV2::HardwareL0);
    request.size = sizeof(request) - 1U;
    Check(state, "v2 rejects a truncated request",
          knhv::SelectProviderV2(&request, &capabilities, &response) ==
              knhv::HvStatus::InvalidParameter);
    request = Request(knhv::HvLeaseModeV2::HardwareL0);
    request.flags = 1U << 31;
    Check(state, "v2 rejects unknown request flags",
          knhv::SelectProviderV2(&request, &capabilities, &response) ==
              knhv::HvStatus::InvalidParameter);

    knhv::HvOwnerLeaseV2 lease = {};
    lease.size = sizeof(lease);
    lease.version = knhv::kAbiV2Version;
    lease.owner_id = 41U;
    lease.generation = capabilities.generation + 1U;
    lease.mode = static_cast<knhv::u32>(knhv::HvLeaseModeV2::HardwareL0);
    lease.flags = knhv::kLeaseFlagExclusive;
    Check(state, "v2 rejects a stale lease generation",
          !knhv::LeaseMatchesCapabilityV2(&lease, &capabilities));
}

}  // namespace

void RunProviderV2Contract(TestState& state) {
    CheckV2Shape(state);
    CheckProviderModes(state);
    CheckProviderFuzzEdges(state);
}

}  // namespace knhv_tests
