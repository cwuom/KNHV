#include "test_support.h"

#include "knhv_exit.h"

namespace knhv_tests {
namespace {

knhv::ExitPolicy MakePolicy() {
    knhv::ExitPolicy policy = {};
    policy.size = sizeof(policy);
    policy.version = knhv::kExitContractVersion;
    policy.level = 1;
    policy.flags = knhv::kExitPolicyVirtualizeCpuid |
                   knhv::kExitPolicyVirtualizeTsc |
                   knhv::kExitPolicyVirtualizeMsr |
                   knhv::kExitPolicyReflectVmx |
                   knhv::kExitPolicyReflectEpt | knhv::kExitPolicyAllowIo;
    policy.allowed_classes = knhv::kExitKnownClassMask;
    policy.max_instruction_length = knhv::kExitMaxInstructionLength;
    policy.generation = 11;
    return policy;
}

knhv::ExitRecord MakeRecord(knhv::ExitReason reason) {
    knhv::ExitRecord record = {};
    record.size = sizeof(record);
    record.version = knhv::kExitContractVersion;
    record.reason = static_cast<std::uint32_t>(reason);
    record.instruction_length = 3;
    record.guest_linear = 0x1000;
    record.guest_physical = 0x2000;
    record.guest_rip = 0x400000;
    record.generation = 11;
    return record;
}

void CheckExitClassification(TestState& state) {
    Check(state, "exit classifier separates nested VMX from time and memory",
          knhv::ClassifyExitReason(
              static_cast<std::uint32_t>(knhv::ExitReason::Vmwrite)) ==
              knhv::ExitClass::NestedVmx &&
              knhv::ClassifyExitReason(
                  static_cast<std::uint32_t>(knhv::ExitReason::Rdtscp)) ==
              knhv::ExitClass::Time &&
              knhv::ClassifyExitReason(
                  static_cast<std::uint32_t>(knhv::ExitReason::EptViolation)) ==
              knhv::ExitClass::Memory);
    Check(state, "exit classifier sends an unknown reason to quarantine",
          knhv::ClassifyExitReason(0x1234) == knhv::ExitClass::Unknown);
}

void CheckExitDecisions(TestState& state) {
    knhv::ExitPolicy policy = MakePolicy();
    knhv::ExitDecision decision = {};
    knhv::ExitRecord record = MakeRecord(knhv::ExitReason::Cpuid);
    Check(state, "CPUID exit uses the local fast path",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::ExitDecisionStatus::Success) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::ExitAction::ResumeGuest));
    record = MakeRecord(knhv::ExitReason::Vmwrite);
    Check(state, "nested VMX exit is reflected to L1",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::ExitAction::ReflectToL1));
    record = MakeRecord(knhv::ExitReason::EptViolation);
    Check(state, "EPT violation is reflected when the EPT policy is enabled",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::ExitAction::ReflectToL1));
    record.flags = knhv::kExitRecordHostOwned;
    Check(state, "host-owned EPT violations quarantine the vCPU",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::ExitDecisionStatus::QuarantineRequired) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::ExitAction::QuarantineVcpu));
    policy.flags &= ~knhv::kExitPolicyReflectVmx;
    record = MakeRecord(knhv::ExitReason::Vmxon);
    Check(state, "unapproved nested VMX exits inject undefined instruction",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::ExitDecisionStatus::UnsupportedReason) &&
              decision.exception_vector == 6);
}

void CheckExitFailures(TestState& state) {
    knhv::ExitPolicy policy = MakePolicy();
    knhv::ExitRecord record = MakeRecord(knhv::ExitReason::Cpuid);
    knhv::ExitDecision decision = {};
    record.generation = 10;
    Check(state, "exit evaluation rejects a stale generation",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::ExitDecisionStatus::GenerationMismatch) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::ExitAction::QuarantineVcpu));
    record = MakeRecord(knhv::ExitReason::Cpuid);
    record.guest_rip = 0x0000800000000000ULL;
    Check(state, "exit evaluation rejects a noncanonical guest RIP",
          !knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::ExitDecisionStatus::InvalidParameter));
    record = MakeRecord(knhv::ExitReason::Cpuid);
    record.reason = 0xFFFF;
    Check(state, "unknown exits never resume the guest",
          knhv::EvaluateExit(&record, &policy, 48, 48, &decision) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::ExitAction::QuarantineVcpu));
    policy = MakePolicy();
    policy.flags |= 1U << 31;
    Check(state, "exit policy rejects unknown policy flags",
          !knhv::IsExitPolicyValid(&policy, 48));
}

}  // namespace

void RunExitModelContract(TestState& state) {
    CheckExitClassification(state);
    CheckExitDecisions(state);
    CheckExitFailures(state);
}

}  // namespace knhv_tests
