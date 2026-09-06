#include "test_support.h"

#include <array>

#include "knhv_vpid.h"

namespace knhv_tests {
namespace {

knhv::VpidRequest MakeRequest(std::uint64_t owner = 42,
                              std::uint64_t generation = 7,
                              std::uint32_t max_vpid = 4) {
    knhv::VpidRequest request = {};
    request.size = sizeof(request);
    request.version = knhv::kVpidContractVersion;
    request.owner_id = owner;
    request.generation = generation;
    request.kind = static_cast<std::uint32_t>(knhv::VpidKind::L2);
    request.max_vpid = max_vpid;
    return request;
}

knhv::VpidLease MakeFreeLease() {
    knhv::VpidLease lease = {};
    lease.size = sizeof(lease);
    lease.version = knhv::kVpidContractVersion;
    lease.state = static_cast<std::uint32_t>(knhv::VpidLeaseState::Free);
    return lease;
}

knhv::VpidLease MakeLease(std::uint32_t vpid,
                          knhv::VpidLeaseState state =
                              knhv::VpidLeaseState::Active) {
    knhv::VpidLease lease = {};
    lease.size = sizeof(lease);
    lease.version = knhv::kVpidContractVersion;
    lease.vpid = vpid;
    lease.kind = static_cast<std::uint32_t>(knhv::VpidKind::L2);
    lease.state = static_cast<std::uint32_t>(state);
    lease.owner_id = 42;
    lease.generation = 7;
    lease.allocation_sequence = vpid;
    return lease;
}

knhv::ShootdownRequest MakeShootdown(knhv::ShootdownType type,
                                      std::uint32_t vpid,
                                      std::uint32_t flags,
                                      std::uint64_t target_mask = 0x7,
                                      std::uint64_t deadline = 100) {
    knhv::ShootdownRequest request = {};
    request.size = sizeof(request);
    request.version = knhv::kVpidContractVersion;
    request.type = static_cast<std::uint32_t>(type);
    request.flags = flags;
    request.request_id = 101;
    request.generation = 7;
    request.source_cpu = 0;
    request.vpid = vpid;
    request.target_cpu_mask = target_mask;
    request.deadline_tsc = deadline;
    return request;
}

void CheckAllocation(TestState& state) {
    const knhv::VpidRequest request = MakeRequest();
    Check(state, "VPID allocation request validates",
          knhv::IsVpidRequestValid(&request));

    std::array<knhv::VpidLease, 3> existing = {
        MakeFreeLease(), MakeFreeLease(), MakeFreeLease()};
    knhv::VpidLease first = {};
    Check(state, "VPID allocator returns the first bounded identifier",
          knhv::AllocateVpid(&request, existing.data(), 3, &first) ==
              knhv::VpidStatus::Success &&
              first.vpid == knhv::kVpidMinimum &&
              first.state ==
                  static_cast<std::uint32_t>(knhv::VpidLeaseState::Active));
    existing[0] = first;
    knhv::VpidLease second = {};
    Check(state, "VPID allocator keeps active identifiers unique",
          knhv::AllocateVpid(&request, existing.data(), 3, &second) ==
              knhv::VpidStatus::Success && second.vpid == first.vpid + 1U);
    Check(state, "allocated VPID carries the owner generation",
          second.owner_id == request.owner_id &&
              second.generation == request.generation &&
              knhv::IsVpidLeaseValid(&second));

    std::array<knhv::VpidLease, 1> occupied = {MakeLease(1)};
    const knhv::VpidRequest one = MakeRequest(42, 7, 1);
    knhv::VpidLease output = {};
    Check(state, "VPID allocator reports exhaustion instead of reusing a lease",
          knhv::AllocateVpid(&one, occupied.data(), 1, &output) ==
              knhv::VpidStatus::Exhausted);

    std::array<knhv::VpidLease, 2> duplicate = {MakeLease(1), MakeLease(1)};
    Check(state, "VPID allocator rejects duplicate live identifiers",
          knhv::AllocateVpid(&request, duplicate.data(), 2, &output) ==
              knhv::VpidStatus::Conflict);
}

void CheckLeaseLifecycle(TestState& state) {
    const knhv::VpidRequest request = MakeRequest();
    knhv::VpidLease lease = {};
    Check(state, "VPID lease lifecycle can allocate a live lease",
          knhv::AllocateVpid(&request, nullptr, 0, &lease) ==
              knhv::VpidStatus::Success);
    Check(state, "VPID retirement rejects a stale generation",
          !knhv::BeginVpidRetire(&lease, request.generation + 1));
    Check(state, "VPID retirement enters the draining state",
          knhv::BeginVpidRetire(&lease, request.generation) &&
              lease.state ==
                  static_cast<std::uint32_t>(knhv::VpidLeaseState::Retiring));

    const knhv::ShootdownRequest request_flush = MakeShootdown(
        knhv::ShootdownType::SingleContext, lease.vpid, 0);
    knhv::ShootdownState flush = {};
    Check(state, "single-context INVVPID request validates",
          knhv::IsShootdownRequestValid(&request_flush) &&
              knhv::BeginShootdown(&request_flush, &flush));
    Check(state, "VPID cannot be reclaimed before shootdown completion",
          !knhv::ReclaimVpid(&lease, request.generation, &flush));
    Check(state, "shootdown waits for every target CPU",
          knhv::AcknowledgeShootdown(&flush, 0) &&
              knhv::AcknowledgeShootdown(&flush, 1) &&
              !knhv::CompleteShootdown(&flush, 50));
    Check(state, "shootdown completes at the deadline after final acknowledgement",
          knhv::AcknowledgeShootdown(&flush, 2) &&
              knhv::CompleteShootdown(&flush, 100) &&
              flush.state == static_cast<std::uint32_t>(
                                  knhv::ShootdownStateKind::Completed));
    Check(state, "completed context invalidation permits VPID reclaim",
          knhv::ReclaimVpid(&lease, request.generation, &flush) &&
              lease.state ==
                  static_cast<std::uint32_t>(knhv::VpidLeaseState::Free) &&
              knhv::IsVpidLeaseValid(&lease));
}

void CheckShootdownBounds(TestState& state) {
    const knhv::ShootdownRequest all_without_opt_in = MakeShootdown(
        knhv::ShootdownType::AllContext, 0, 0);
    Check(state, "all-context invalidation requires an explicit opt-in",
          !knhv::IsShootdownRequestValid(&all_without_opt_in));
    const knhv::ShootdownRequest all = MakeShootdown(
        knhv::ShootdownType::AllContext, 0, knhv::kShootdownAllowAllContext);
    Check(state, "all-context invalidation validates with the opt-in flag",
          knhv::IsShootdownRequestValid(&all));
    const knhv::ShootdownRequest retain = MakeShootdown(
        knhv::ShootdownType::SingleContextRetainGlobals, 2,
        knhv::kShootdownRetainGlobals);
    Check(state, "single-context retaining globals validates independently",
          knhv::IsShootdownRequestValid(&retain));
    knhv::ShootdownRequest bad = retain;
    bad.flags = 0;
    Check(state, "retaining-globals requests reject missing policy flags",
          !knhv::IsShootdownRequestValid(&bad));
    bad = retain;
    bad.source_cpu = knhv::kVpidMaxCpus;
    Check(state, "shootdown requests reject an out-of-range source CPU",
          !knhv::IsShootdownRequestValid(&bad));

    knhv::ShootdownState state_flush = {};
    Check(state, "shootdown state begins in a validated pending state",
          knhv::BeginShootdown(&retain, &state_flush) &&
              knhv::IsShootdownStateValid(&state_flush));
    Check(state, "shootdown rejects acknowledgements outside its target set",
          !knhv::AcknowledgeShootdown(&state_flush, 3));
    Check(state, "late shootdown is marked timed out",
          !knhv::CompleteShootdown(&state_flush, 101) &&
              state_flush.state == static_cast<std::uint32_t>(
                                        knhv::ShootdownStateKind::TimedOut));
    Check(state, "timed-out shootdown is quarantined before reuse",
          knhv::QuarantineShootdown(&state_flush) &&
              state_flush.state == static_cast<std::uint32_t>(
                                        knhv::ShootdownStateKind::Quarantined));
}

void CheckQuarantineAndInvalidInputs(TestState& state) {
    knhv::VpidLease lease = MakeLease(3);
    Check(state, "VPID quarantine preserves a live identifier for diagnosis",
          knhv::QuarantineVpid(&lease, 7) &&
              lease.state == static_cast<std::uint32_t>(
                                  knhv::VpidLeaseState::Quarantined));
    Check(state, "quarantined VPID cannot be retired again",
          !knhv::BeginVpidRetire(&lease, 7));
    knhv::VpidRequest invalid = MakeRequest();
    invalid.max_vpid = 0;
    Check(state, "VPID requests reject a zero identifier limit",
          !knhv::IsVpidRequestValid(&invalid));
    invalid = MakeRequest();
    invalid.reserved = 1;
    Check(state, "VPID requests reject nonzero reserved fields",
          !knhv::IsVpidRequestValid(&invalid));
    knhv::VpidLease malformed = MakeLease(0);
    Check(state, "VPID leases reject a zero live identifier",
          !knhv::IsVpidLeaseValid(&malformed));
}

}  // namespace

void RunVpidModelContract(TestState& state) {
    CheckAllocation(state);
    CheckLeaseLifecycle(state);
    CheckShootdownBounds(state);
    CheckQuarantineAndInvalidInputs(state);
}

}  // namespace knhv_tests
