#include "knhv_vpid.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kVpidContractVersion && size >= required &&
           size <= kVpidMaxStructSize;
}

bool IsVpidValueValid(u32 value) {
    return value >= kVpidMinimum && value <= kVpidMaximum;
}

bool IsKindValid(u32 value) {
    return value >= static_cast<u32>(VpidKind::Root) &&
           value <= static_cast<u32>(VpidKind::L2);
}

bool IsLeaseStateValid(u32 value) {
    return value <= static_cast<u32>(VpidLeaseState::Quarantined);
}

bool IsShootdownTypeValid(u32 value) {
    return value <= static_cast<u32>(ShootdownType::SingleContextRetainGlobals);
}

bool IsShootdownStateValidValue(u32 value) {
    return value <= static_cast<u32>(ShootdownStateKind::Quarantined);
}

bool IsContextShootdown(u32 type) {
    return type == static_cast<u32>(ShootdownType::SingleContext) ||
           type == static_cast<u32>(ShootdownType::SingleContextRetainGlobals);
}

void InitializeFreeLease(VpidLease* lease) {
    *lease = {};
    lease->size = sizeof(*lease);
    lease->version = kVpidContractVersion;
    lease->state = static_cast<u32>(VpidLeaseState::Free);
}

void InitializeShootdownState(ShootdownState* state) {
    *state = {};
    state->size = sizeof(*state);
    state->version = kVpidContractVersion;
    state->state = static_cast<u32>(ShootdownStateKind::Idle);
}

bool IsShootdownPayloadValid(u32 type, u32 vpid) {
    if (!IsShootdownTypeValid(type)) return false;
    switch (static_cast<ShootdownType>(type)) {
        case ShootdownType::SingleAddress:
        case ShootdownType::SingleContext:
        case ShootdownType::SingleContextRetainGlobals:
            return IsVpidValueValid(vpid);
        case ShootdownType::AllContext:
            return vpid == 0;
        default:
            return false;
    }
}

bool ShootdownCoversVpid(const ShootdownState& state, u32 vpid) {
    if (state.state != static_cast<u32>(ShootdownStateKind::Completed)) {
        return false;
    }
    if (state.type == static_cast<u32>(ShootdownType::AllContext)) {
        return true;
    }
    return IsContextShootdown(state.type) && state.vpid == vpid;
}

bool IsVpidUsed(const VpidLease* existing, u32 count, u32 vpid) {
    for (u32 index = 0; index < count; ++index) {
        if (existing[index].state !=
                static_cast<u32>(VpidLeaseState::Free) &&
            existing[index].vpid == vpid) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool IsVpidRequestValid(const VpidRequest* request) {
    return request != nullptr &&
           IsVersionedSizeValid(request->version, request->size,
                                sizeof(VpidRequest)) &&
           request->owner_id != 0 && request->generation != 0 &&
           IsKindValid(request->kind) &&
           request->max_vpid >= kVpidMinimum &&
           request->max_vpid <= kVpidMaximum && request->reserved == 0 &&
           request->reserved2 == 0;
}

bool IsVpidLeaseValid(const VpidLease* lease) {
    if (lease == nullptr ||
        !IsVersionedSizeValid(lease->version, lease->size,
                              sizeof(VpidLease)) ||
        (lease->flags & ~kVpidKnownLeaseFlagMask) != 0 ||
        !IsLeaseStateValid(lease->state)) {
        return false;
    }
    const auto state = static_cast<VpidLeaseState>(lease->state);
    if (state == VpidLeaseState::Free) {
        return lease->vpid == 0 && lease->kind == 0 && lease->owner_id == 0 &&
               lease->generation == 0 && lease->allocation_sequence == 0;
    }
    return IsVpidValueValid(lease->vpid) && IsKindValid(lease->kind) &&
           lease->owner_id != 0 && lease->generation != 0 &&
           lease->allocation_sequence != 0;
}

VpidStatus AllocateVpid(const VpidRequest* request,
                        const VpidLease* existing, u32 existing_count,
                        VpidLease* lease) {
    if (lease == nullptr) return VpidStatus::InvalidParameter;
    InitializeFreeLease(lease);
    if (!IsVpidRequestValid(request) || existing_count > kVpidMaxLeases ||
        (existing_count != 0 && existing == nullptr)) {
        return VpidStatus::InvalidParameter;
    }
    for (u32 index = 0; index < existing_count; ++index) {
        if (!IsVpidLeaseValid(&existing[index])) {
            return VpidStatus::InvalidParameter;
        }
        if (existing[index].state ==
            static_cast<u32>(VpidLeaseState::Free)) {
            continue;
        }
        for (u32 prior = 0; prior < index; ++prior) {
            if (existing[prior].state !=
                    static_cast<u32>(VpidLeaseState::Free) &&
                existing[prior].vpid == existing[index].vpid) {
                return VpidStatus::Conflict;
            }
        }
    }
    for (u32 candidate = kVpidMinimum; candidate <= request->max_vpid;
         ++candidate) {
        if (IsVpidUsed(existing, existing_count, candidate)) continue;
        lease->vpid = candidate;
        lease->kind = request->kind;
        lease->state = static_cast<u32>(VpidLeaseState::Active);
        lease->owner_id = request->owner_id;
        lease->generation = request->generation;
        // the generation is part of the lease identity, so a reused number
        // cannot be accepted by a stale generation
        lease->allocation_sequence = static_cast<u64>(candidate);
        return VpidStatus::Success;
    }
    return VpidStatus::Exhausted;
}

bool BeginVpidRetire(VpidLease* lease, u64 generation) {
    if (!IsVpidLeaseValid(lease) || generation == 0 ||
        lease->generation != generation ||
        lease->state != static_cast<u32>(VpidLeaseState::Active)) {
        return false;
    }
    lease->state = static_cast<u32>(VpidLeaseState::Retiring);
    return true;
}

bool ReclaimVpid(VpidLease* lease, u64 generation,
                 const ShootdownState* shootdown) {
    if (!IsVpidLeaseValid(lease) || shootdown == nullptr || generation == 0 ||
        lease->state != static_cast<u32>(VpidLeaseState::Retiring) ||
        lease->generation != generation ||
        !IsShootdownStateValid(shootdown) ||
        shootdown->generation != generation ||
        shootdown->acknowledged_cpu_mask != shootdown->target_cpu_mask ||
        !ShootdownCoversVpid(*shootdown, lease->vpid)) {
        return false;
    }
    InitializeFreeLease(lease);
    return true;
}

bool QuarantineVpid(VpidLease* lease, u64 generation) {
    if (!IsVpidLeaseValid(lease) || generation == 0 ||
        lease->generation != generation ||
        (lease->state != static_cast<u32>(VpidLeaseState::Active) &&
         lease->state != static_cast<u32>(VpidLeaseState::Retiring))) {
        return false;
    }
    lease->state = static_cast<u32>(VpidLeaseState::Quarantined);
    return true;
}

bool IsShootdownRequestValid(const ShootdownRequest* request) {
    if (request == nullptr ||
        !IsVersionedSizeValid(request->version, request->size,
                              sizeof(ShootdownRequest)) ||
        (request->flags & ~kShootdownKnownFlagMask) != 0 ||
        request->request_id == 0 || request->generation == 0 ||
        request->source_cpu >= kVpidMaxCpus || request->target_cpu_mask == 0 ||
        request->deadline_tsc == 0 ||
        !IsShootdownPayloadValid(request->type, request->vpid)) {
        return false;
    }
    const auto type = static_cast<ShootdownType>(request->type);
    if (type == ShootdownType::SingleAddress) {
        return request->flags == 0;
    }
    if (type == ShootdownType::SingleContext) {
        return request->flags == 0 && request->address == 0;
    }
    if (type == ShootdownType::AllContext) {
        return (request->flags & kShootdownAllowAllContext) != 0 &&
               (request->flags & kShootdownRetainGlobals) == 0 &&
               request->address == 0;
    }
    return (request->flags & kShootdownRetainGlobals) != 0 &&
           (request->flags & kShootdownAllowAllContext) == 0 &&
           request->address == 0;
}

bool IsShootdownStateValid(const ShootdownState* state) {
    if (state == nullptr ||
        !IsVersionedSizeValid(state->version, state->size,
                              sizeof(ShootdownState)) ||
        state->reserved != 0 || !IsShootdownStateValidValue(state->state)) {
        return false;
    }
    const auto state_kind = static_cast<ShootdownStateKind>(state->state);
    if (state_kind == ShootdownStateKind::Idle) {
        return state->type == 0 && state->request_id == 0 &&
               state->generation == 0 && state->target_cpu_mask == 0 &&
               state->acknowledged_cpu_mask == 0 && state->deadline_tsc == 0 &&
               state->vpid == 0;
    }
    if (state->request_id == 0 || state->generation == 0 ||
        state->target_cpu_mask == 0 || state->deadline_tsc == 0 ||
        !IsShootdownPayloadValid(state->type, state->vpid) ||
        (state->acknowledged_cpu_mask & ~state->target_cpu_mask) != 0) {
        return false;
    }
    if (state_kind == ShootdownStateKind::Completed) {
        return state->acknowledged_cpu_mask == state->target_cpu_mask;
    }
    if (state_kind == ShootdownStateKind::TimedOut) {
        return state->acknowledged_cpu_mask != state->target_cpu_mask;
    }
    return true;
}

bool BeginShootdown(const ShootdownRequest* request, ShootdownState* state) {
    if (state == nullptr) return false;
    InitializeShootdownState(state);
    if (!IsShootdownRequestValid(request)) return false;
    state->type = request->type;
    state->request_id = request->request_id;
    state->generation = request->generation;
    state->target_cpu_mask = request->target_cpu_mask;
    state->deadline_tsc = request->deadline_tsc;
    state->vpid = request->vpid;
    state->state = static_cast<u32>(ShootdownStateKind::Pending);
    return true;
}

bool AcknowledgeShootdown(ShootdownState* state, u32 cpu_index) {
    if (!IsShootdownStateValid(state) ||
        state->state != static_cast<u32>(ShootdownStateKind::Pending) ||
        cpu_index >= kVpidMaxCpus) {
        return false;
    }
    const u64 bit = 1ULL << cpu_index;
    if ((state->target_cpu_mask & bit) == 0) return false;
    state->acknowledged_cpu_mask |= bit;
    return true;
}

bool CompleteShootdown(ShootdownState* state, u64 now_tsc) {
    if (!IsShootdownStateValid(state) ||
        state->state != static_cast<u32>(ShootdownStateKind::Pending)) {
        return false;
    }
    if (now_tsc > state->deadline_tsc) {
        state->state = static_cast<u32>(ShootdownStateKind::TimedOut);
        return false;
    }
    if (state->acknowledged_cpu_mask != state->target_cpu_mask) return false;
    state->state = static_cast<u32>(ShootdownStateKind::Completed);
    return true;
}

bool QuarantineShootdown(ShootdownState* state) {
    if (!IsShootdownStateValid(state) ||
        (state->state != static_cast<u32>(ShootdownStateKind::Pending) &&
         state->state != static_cast<u32>(ShootdownStateKind::TimedOut))) {
        return false;
    }
    state->state = static_cast<u32>(ShootdownStateKind::Quarantined);
    return true;
}

}  // namespace knhv
