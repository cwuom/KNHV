#include "knhv_interrupt.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kInterruptContractVersion && size >= required &&
           size <= kInterruptMaxStructSize;
}

bool IsKindValid(u32 kind) {
    return kind <= static_cast<u32>(InterruptKind::Smi);
}

bool IsVectorValid(InterruptKind kind, u32 vector) {
    switch (kind) {
        case InterruptKind::HardwareException:
            return vector < kInterruptVectorFirstExternal;
        case InterruptKind::External:
        case InterruptKind::Virtual:
            return vector >= kInterruptVectorFirstExternal &&
                   vector < kInterruptVectorCount;
        case InterruptKind::Nmi:
            return vector == 2U;
        case InterruptKind::Init:
        case InterruptKind::Smi:
            return vector == 0U;
        case InterruptKind::Sipi:
            return vector < kInterruptVectorCount;
        default:
            return false;
    }
}

u32 Priority(const InterruptEvent& event) {
    switch (static_cast<InterruptKind>(event.kind)) {
        case InterruptKind::Nmi:
            return 4U;
        case InterruptKind::HardwareException:
            return 3U;
        case InterruptKind::Init:
        case InterruptKind::Sipi:
        case InterruptKind::Smi:
            return 2U;
        case InterruptKind::External:
        case InterruptKind::Virtual:
            return 1U;
        default:
            return 0U;
    }
}

bool IsBlocked(const InterruptState& state, const InterruptEvent& event) {
    const auto kind = static_cast<InterruptKind>(event.kind);
    if (kind == InterruptKind::Nmi) {
        return (state.interruptibility & kInterruptBlockNmi) != 0;
    }
    if (kind == InterruptKind::External || kind == InterruptKind::Virtual) {
        if ((state.interruptibility &
             (kInterruptBlockBySti | kInterruptBlockByMovSs)) != 0) {
            return true;
        }
        return (event.vector >> 4U) <= (state.virtual_apic_tpr >> 4U);
    }
    return false;
}

bool IsSameEvent(const InterruptEvent& left, const InterruptDecision& right) {
    return left.kind == right.kind && left.vector == right.vector &&
           left.error_code == right.error_code && left.flags == right.flags &&
           left.sequence == right.sequence &&
           left.generation == right.generation;
}

void InitializeDecision(u64 generation, InterruptDecision* decision) {
    *decision = {};
    decision->size = sizeof(*decision);
    decision->version = kInterruptContractVersion;
    decision->generation = generation;
}

}  // namespace

bool IsInterruptEventValid(const InterruptEvent* event) {
    if (event == nullptr ||
        !IsVersionedSizeValid(event->version, event->size,
                              sizeof(InterruptEvent)) ||
        !IsKindValid(event->kind) ||
        !IsVectorValid(static_cast<InterruptKind>(event->kind), event->vector) ||
        (event->flags & ~kInterruptKnownEventMask) != 0 ||
        event->reserved != 0 || event->reserved2 != 0 ||
        event->generation == 0 || event->sequence == 0) {
        return false;
    }
    if ((event->flags & kInterruptEventDeliverError) != 0 &&
        static_cast<InterruptKind>(event->kind) !=
            InterruptKind::HardwareException) {
        return false;
    }
    if ((event->flags & kInterruptEventDeliverError) == 0 &&
        event->error_code != 0) {
        return false;
    }
    return true;
}

bool IsInterruptStateValid(const InterruptState* state) {
    if (state == nullptr ||
        !IsVersionedSizeValid(state->version, state->size,
                              sizeof(InterruptState)) ||
        state->generation == 0 || state->next_sequence == 0 ||
        state->pending_count > kInterruptQueueDepth ||
        (state->interruptibility & ~kInterruptKnownBlockMask) != 0 ||
        state->virtual_apic_tpr > 0xFFU || state->reserved != 0) {
        return false;
    }
    for (u32 index = 0; index < state->pending_count; ++index) {
        const InterruptEvent& event = state->pending[index];
        if (!IsInterruptEventValid(&event) ||
            event.generation != state->generation) {
            return false;
        }
        for (u32 prior = 0; prior < index; ++prior) {
            if (state->pending[prior].sequence == event.sequence) return false;
        }
    }
    for (u32 index = state->pending_count; index < kInterruptQueueDepth;
         ++index) {
        const InterruptEvent& event = state->pending[index];
        if (event.size != 0 || event.version != 0 || event.kind != 0 ||
            event.vector != 0 || event.error_code != 0 || event.flags != 0 ||
            event.reserved != 0 || event.reserved2 != 0 ||
            event.source_id != 0 || event.generation != 0 ||
            event.sequence != 0) {
            return false;
        }
    }
    return true;
}

InterruptStatus EnqueueInterrupt(InterruptState* state,
                                  const InterruptEvent* event) {
    if (!IsInterruptStateValid(state) || !IsInterruptEventValid(event)) {
        return InterruptStatus::Invalid;
    }
    if (event->generation != state->generation) {
        return InterruptStatus::GenerationMismatch;
    }
    if (state->pending_count >= kInterruptQueueDepth) {
        return InterruptStatus::QueueFull;
    }
    for (u32 index = 0; index < state->pending_count; ++index) {
        if (state->pending[index].sequence == event->sequence) {
            return InterruptStatus::Conflict;
        }
    }
    if (event->sequence == ~0ULL) return InterruptStatus::Conflict;
    state->pending[state->pending_count] = *event;
    ++state->pending_count;
    if (event->sequence >= state->next_sequence) {
        state->next_sequence = event->sequence + 1ULL;
    }
    return InterruptStatus::Ready;
}

InterruptStatus SelectInterrupt(const InterruptState* state, u64 generation,
                                 InterruptDecision* decision) {
    if (decision == nullptr) return InterruptStatus::Invalid;
    InitializeDecision(generation, decision);
    if (!IsInterruptStateValid(state)) {
        decision->action = static_cast<u32>(InterruptAction::Quarantine);
        return InterruptStatus::Invalid;
    }
    if (state->generation != generation) {
        decision->action = static_cast<u32>(InterruptAction::Quarantine);
        return InterruptStatus::GenerationMismatch;
    }
    if (state->pending_count == 0) {
        decision->status = static_cast<u32>(InterruptStatus::NoPending);
        decision->action = static_cast<u32>(InterruptAction::WaitWindow);
        return InterruptStatus::NoPending;
    }
    const InterruptEvent* selected = nullptr;
    for (u32 index = 0; index < state->pending_count; ++index) {
        const InterruptEvent& candidate = state->pending[index];
        if (IsBlocked(*state, candidate)) continue;
        if (selected == nullptr || Priority(candidate) > Priority(*selected) ||
            (Priority(candidate) == Priority(*selected) &&
             candidate.sequence < selected->sequence)) {
            selected = &candidate;
        }
    }
    if (selected == nullptr) {
        decision->status = static_cast<u32>(InterruptStatus::Blocked);
        decision->action = static_cast<u32>(InterruptAction::WaitWindow);
        return InterruptStatus::Blocked;
    }
    decision->status = static_cast<u32>(InterruptStatus::Ready);
    decision->action = static_cast<u32>(InterruptAction::Inject);
    decision->kind = selected->kind;
    decision->vector = selected->vector;
    decision->error_code = selected->error_code;
    decision->flags = selected->flags;
    decision->sequence = selected->sequence;
    return InterruptStatus::Ready;
}

bool CommitInterruptInjection(InterruptState* state,
                              const InterruptDecision* decision) {
    if (!IsInterruptStateValid(state) || decision == nullptr ||
        !IsVersionedSizeValid(decision->version, decision->size,
                              sizeof(InterruptDecision)) ||
        decision->status != static_cast<u32>(InterruptStatus::Ready) ||
        decision->action != static_cast<u32>(InterruptAction::Inject) ||
        decision->generation != state->generation || decision->sequence == 0 ||
        decision->reserved != 0 || decision->reserved2 != 0 ||
        (decision->flags & ~kInterruptKnownEventMask) != 0) {
        return false;
    }
    for (u32 index = 0; index < state->pending_count; ++index) {
        if (!IsSameEvent(state->pending[index], *decision)) continue;
        const auto kind = static_cast<InterruptKind>(decision->kind);
        for (u32 move = index + 1; move < state->pending_count; ++move) {
            state->pending[move - 1] = state->pending[move];
        }
        --state->pending_count;
        state->pending[state->pending_count] = {};
        if (kind == InterruptKind::Nmi) {
            state->interruptibility |= kInterruptBlockNmi;
        }
        return true;
    }
    return false;
}

bool IsPostedInterruptValid(const PostedInterruptDescriptor* descriptor) {
    return descriptor != nullptr &&
           IsVersionedSizeValid(descriptor->version, descriptor->size,
                                sizeof(PostedInterruptDescriptor)) &&
           descriptor->notification_vector >= kInterruptVectorFirstExternal &&
           descriptor->notification_vector < kInterruptVectorCount &&
           descriptor->suppress_notification <= 1U &&
           descriptor->reserved == 0 && descriptor->reserved2 == 0 &&
           descriptor->generation != 0;
}

bool PostInterrupt(PostedInterruptDescriptor* descriptor, u32 vector,
                   u64 generation) {
    if (!IsPostedInterruptValid(descriptor) ||
        vector < kInterruptVectorFirstExternal ||
        vector >= kInterruptVectorCount || descriptor->generation != generation) {
        return false;
    }
    const u32 word = vector >> 5U;
    const u32 bit = vector & 31U;
    descriptor->pir[word] |= 1U << bit;
    return true;
}

InterruptStatus DrainPostedInterrupt(PostedInterruptDescriptor* descriptor,
                                      InterruptState* state, u64 generation,
                                      u64 source_id) {
    if (!IsPostedInterruptValid(descriptor) ||
        !IsInterruptStateValid(state)) {
        return InterruptStatus::Invalid;
    }
    if (descriptor->generation != generation || state->generation != generation) {
        return InterruptStatus::GenerationMismatch;
    }
    bool drained = false;
    for (u32 word = 0; word < 8U; ++word) {
        u32 bits = descriptor->pir[word];
        for (u32 bit = 0; bit < 32U; ++bit) {
            const u32 mask = 1U << bit;
            if ((bits & mask) == 0) continue;
            InterruptEvent event = {};
            event.size = sizeof(event);
            event.version = kInterruptContractVersion;
            event.kind = static_cast<u32>(InterruptKind::Virtual);
            event.vector = (word << 5U) + bit;
            event.flags = kInterruptEventPosted | kInterruptEventFromDevice;
            event.source_id = source_id;
            event.generation = generation;
            if (state->next_sequence == ~0ULL) return InterruptStatus::Conflict;
            event.sequence = state->next_sequence;
            const InterruptStatus status = EnqueueInterrupt(state, &event);
            if (status != InterruptStatus::Ready) return status;
            descriptor->pir[word] &= ~mask;
            drained = true;
        }
    }
    return drained ? InterruptStatus::Ready : InterruptStatus::NoPending;
}

}  // namespace knhv
