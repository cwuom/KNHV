#include "test_support.h"

#include "knhv_interrupt.h"

namespace knhv_tests {
namespace {

knhv::InterruptState MakeState() {
    knhv::InterruptState state = {};
    state.size = sizeof(state);
    state.version = knhv::kInterruptContractVersion;
    state.generation = 9;
    state.next_sequence = 1;
    return state;
}

knhv::InterruptEvent MakeEvent(knhv::InterruptKind kind, std::uint32_t vector,
                               std::uint64_t sequence) {
    knhv::InterruptEvent event = {};
    event.size = sizeof(event);
    event.version = knhv::kInterruptContractVersion;
    event.kind = static_cast<std::uint32_t>(kind);
    event.vector = vector;
    event.generation = 9;
    event.sequence = sequence;
    return event;
}

knhv::PostedInterruptDescriptor MakePosted() {
    knhv::PostedInterruptDescriptor descriptor = {};
    descriptor.size = sizeof(descriptor);
    descriptor.version = knhv::kInterruptContractVersion;
    descriptor.notification_vector = 0xF0;
    descriptor.generation = 9;
    return descriptor;
}

void CheckEventQueue(TestState& state) {
    knhv::InterruptState interrupt_state = MakeState();
    Check(state, "interrupt state starts with a bounded empty queue",
          knhv::IsInterruptStateValid(&interrupt_state));
    const knhv::InterruptEvent external =
        MakeEvent(knhv::InterruptKind::External, 0x40, 1);
    const knhv::InterruptEvent nmi =
        MakeEvent(knhv::InterruptKind::Nmi, 2, 2);
    const knhv::InterruptEvent exception =
        MakeEvent(knhv::InterruptKind::HardwareException, 14, 3);
    Check(state, "interrupt queue accepts generation-matched events",
          knhv::EnqueueInterrupt(&interrupt_state, &external) ==
              knhv::InterruptStatus::Ready &&
              knhv::EnqueueInterrupt(&interrupt_state, &nmi) ==
              knhv::InterruptStatus::Ready &&
              knhv::EnqueueInterrupt(&interrupt_state, &exception) ==
              knhv::InterruptStatus::Ready);
    knhv::InterruptDecision decision = {};
    Check(state, "NMI has priority over an external interrupt",
          knhv::SelectInterrupt(&interrupt_state, 9, &decision) ==
              knhv::InterruptStatus::Ready &&
              decision.kind == static_cast<std::uint32_t>(
                                    knhv::InterruptKind::Nmi) &&
              decision.vector == 2);
    Check(state, "injection commit removes exactly the selected event",
          knhv::CommitInterruptInjection(&interrupt_state, &decision) &&
              interrupt_state.pending_count == 2);
    Check(state, "hardware exceptions remain eligible while NMI is blocked",
          knhv::SelectInterrupt(&interrupt_state, 9, &decision) ==
              knhv::InterruptStatus::Ready &&
              decision.kind == static_cast<std::uint32_t>(
                                    knhv::InterruptKind::HardwareException));
    Check(state, "a stale queue generation is rejected",
          knhv::SelectInterrupt(&interrupt_state, 8, &decision) ==
              knhv::InterruptStatus::GenerationMismatch &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::InterruptAction::Quarantine));
    const knhv::InterruptEvent stale =
        MakeEvent(knhv::InterruptKind::External, 0x41, 4);
    knhv::InterruptEvent stale_copy = stale;
    stale_copy.generation = 8;
    Check(state, "enqueue rejects a stale event generation",
          knhv::EnqueueInterrupt(&interrupt_state, &stale_copy) ==
              knhv::InterruptStatus::GenerationMismatch);
}

void CheckBlockingAndBounds(TestState& state) {
    knhv::InterruptState interrupt_state = MakeState();
    interrupt_state.interruptibility = knhv::kInterruptBlockBySti;
    const knhv::InterruptEvent external =
        MakeEvent(knhv::InterruptKind::External, 0x40, 1);
    Check(state, "STI blocking defers external interrupt injection",
          knhv::EnqueueInterrupt(&interrupt_state, &external) ==
              knhv::InterruptStatus::Ready);
    knhv::InterruptDecision decision = {};
    Check(state, "blocked external interrupt requests an interrupt window",
          knhv::SelectInterrupt(&interrupt_state, 9, &decision) ==
              knhv::InterruptStatus::Blocked &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::InterruptAction::WaitWindow));
    interrupt_state.interruptibility = 0;
    interrupt_state.virtual_apic_tpr = 0xF0;
    Check(state, "virtual APIC TPR can defer a low-priority vector",
          knhv::SelectInterrupt(&interrupt_state, 9, &decision) ==
              knhv::InterruptStatus::Blocked);
    interrupt_state.virtual_apic_tpr = 0;
    Check(state, "clearing TPR makes the pending vector injectable",
          knhv::SelectInterrupt(&interrupt_state, 9, &decision) ==
              knhv::InterruptStatus::Ready);
    knhv::InterruptState full = MakeState();
    for (std::uint64_t sequence = 1;
         sequence <= knhv::kInterruptQueueDepth; ++sequence) {
        const knhv::InterruptEvent event =
            MakeEvent(knhv::InterruptKind::External, 0x40,
                      sequence);
        Check(state, "interrupt queue accepts a bounded entry",
              knhv::EnqueueInterrupt(&full, &event) ==
                  knhv::InterruptStatus::Ready);
    }
    const knhv::InterruptEvent overflow =
        MakeEvent(knhv::InterruptKind::External, 0x41, 100);
    Check(state, "interrupt queue rejects an overflow entry",
          knhv::EnqueueInterrupt(&full, &overflow) ==
              knhv::InterruptStatus::QueueFull);
    knhv::InterruptEvent invalid =
        MakeEvent(knhv::InterruptKind::External, 3, 1);
    Check(state, "interrupt events reject invalid vector classes",
          !knhv::IsInterruptEventValid(&invalid));
    invalid = MakeEvent(knhv::InterruptKind::HardwareException, 13, 1);
    invalid.error_code = 1;
    Check(state, "interrupt events require an explicit error-code flag",
          !knhv::IsInterruptEventValid(&invalid));
}

void CheckPostedInterrupts(TestState& state) {
    knhv::InterruptState interrupt_state = MakeState();
    knhv::PostedInterruptDescriptor descriptor = MakePosted();
    Check(state, "posted-interrupt descriptor validates its notification vector",
          knhv::IsPostedInterruptValid(&descriptor));
    Check(state, "posted interrupt sets and coalesces a PIR bit",
          knhv::PostInterrupt(&descriptor, 0x45, 9) &&
              knhv::PostInterrupt(&descriptor, 0x45, 9) &&
              knhv::PostInterrupt(&descriptor, 0xE0, 9));
    Check(state, "posted interrupt drains into virtual device events",
          knhv::DrainPostedInterrupt(&descriptor, &interrupt_state, 9, 77) ==
              knhv::InterruptStatus::Ready &&
              interrupt_state.pending_count == 2 && descriptor.pir[1] == 0 &&
              descriptor.pir[7] == 0);
    knhv::InterruptDecision decision = {};
    Check(state, "posted event carries device provenance",
          knhv::SelectInterrupt(&interrupt_state, 9, &decision) ==
              knhv::InterruptStatus::Ready &&
              (decision.flags & knhv::kInterruptEventFromDevice) != 0 &&
              (decision.flags & knhv::kInterruptEventPosted) != 0);
    Check(state, "empty posted bitmap reports no pending work",
          knhv::DrainPostedInterrupt(&descriptor, &interrupt_state, 9, 77) ==
              knhv::InterruptStatus::NoPending);
    Check(state, "posted interrupt rejects a stale generation",
          !knhv::PostInterrupt(&descriptor, 0x50, 8));
    descriptor.suppress_notification = 2;
    Check(state, "posted descriptor rejects unknown suppression values",
          !knhv::IsPostedInterruptValid(&descriptor));
}

}  // namespace

void RunInterruptModelContract(TestState& state) {
    CheckEventQueue(state);
    CheckBlockingAndBounds(state);
    CheckPostedInterrupts(state);
}

}  // namespace knhv_tests
