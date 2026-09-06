#include "test_support.h"

#include "knhv_cpu_policy.h"

namespace knhv_tests {
namespace {

knhv::CpuidPolicy MakeCpuidPolicy() {
    knhv::CpuidPolicy policy = {};
    policy.size = sizeof(policy);
    policy.version = knhv::kCpuPolicyContractVersion;
    policy.level = 1;
    policy.flags = knhv::kCpuidExposeVmx |
                   knhv::kCpuidExposeHypervisor |
                   knhv::kCpuidPreserveTopology |
                   knhv::kCpuidExposeInvariantTsc;
    policy.generation = 5;
    policy.max_basic_leaf = 0x1FU;
    policy.max_extended_leaf = 0x80000008U;
    policy.rule_count = 2;
    policy.rules[0].leaf = 1;
    policy.rules[0].eax_and = 0xFFFFFFFFU;
    policy.rules[0].ebx_and = 0xFFFFFFFFU;
    policy.rules[0].ecx_and = 0xFFFFFFFFU;
    policy.rules[0].edx_and = 0xFFFFFFFFU;
    policy.rules[1].leaf = 7;
    policy.rules[1].eax_and = 0xFFFFFFFFU;
    policy.rules[1].ebx_and = 0xFFFFFFFFU & ~(1U << 5);
    policy.rules[1].ecx_and = 0xFFFFFFFFU;
    policy.rules[1].edx_and = 0xFFFFFFFFU;
    policy.hypervisor_leaf = {0x40000010U, 0x4B4E4856U, 0x00000001U,
                              0x564D4F44U};
    return policy;
}

knhv::MsrRule MakeVirtualizedRule(std::uint32_t msr,
                                  std::uint64_t read_mask,
                                  std::uint64_t write_mask,
                                  std::uint64_t required_one) {
    knhv::MsrRule rule = {};
    rule.msr = msr;
    rule.read_action =
        static_cast<std::uint32_t>(knhv::MsrAction::Virtualized);
    rule.write_action =
        static_cast<std::uint32_t>(knhv::MsrAction::Virtualized);
    rule.read_mask = read_mask;
    rule.write_allowed_mask = write_mask;
    rule.write_required_one = required_one;
    return rule;
}

knhv::MsrPolicy MakeMsrPolicy() {
    knhv::MsrPolicy policy = {};
    policy.size = sizeof(policy);
    policy.version = knhv::kCpuPolicyContractVersion;
    policy.level = 2;
    policy.flags = knhv::kMsrPolicyAllowPassThrough |
                   knhv::kMsrPolicyAllowTsc | knhv::kMsrPolicyAllowPat;
    policy.generation = 5;
    policy.rule_count = 4;
    policy.rules[0] = MakeVirtualizedRule(knhv::kMsrIa32Tsc, ~0ULL,
                                          0x0000FFFFFFFFFFFFULL, 0);
    policy.rules[1] = MakeVirtualizedRule(knhv::kMsrIa32Pat, ~0ULL, ~0ULL, 0);
    policy.rules[2].msr = knhv::kMsrFsBase;
    policy.rules[2].read_action =
        static_cast<std::uint32_t>(knhv::MsrAction::PassThrough);
    policy.rules[2].write_action =
        static_cast<std::uint32_t>(knhv::MsrAction::PassThrough);
    policy.rules[3].msr = knhv::kMsrIa32Efer;
    policy.rules[3].read_action =
        static_cast<std::uint32_t>(knhv::MsrAction::Virtualized);
    policy.rules[3].write_action =
        static_cast<std::uint32_t>(knhv::MsrAction::InjectGeneralProtection);
    policy.rules[3].read_mask = 0xD01ULL;
    return policy;
}

void CheckCpuidPolicy(TestState& state) {
    knhv::CpuidPolicy policy = MakeCpuidPolicy();
    Check(state, "CPUID policy validates bounded unique rules",
          knhv::IsCpuidPolicyValid(&policy));
    const knhv::CpuidResult host = {0x000906E9U, 0, knhv::kCpuidLeaf1EcxVmx,
                                    0};
    knhv::CpuidResult guest = {};
    const knhv::CpuidResult max_leaf = {0xFFU, 0, 0, 0};
    Check(state, "CPUID policy clamps the advertised basic leaf",
          knhv::FilterCpuid(&policy, 0, 0, &max_leaf, &guest) &&
              guest.eax == policy.max_basic_leaf);
    Check(state, "CPUID policy preserves host VMX only when explicitly exposed",
          knhv::FilterCpuid(&policy, 1, 0, &host, &guest) &&
              (guest.ecx & knhv::kCpuidLeaf1EcxVmx) != 0 &&
              (guest.ecx & knhv::kCpuidLeaf1EcxHypervisor) != 0);
    policy.flags &= ~knhv::kCpuidExposeVmx;
    Check(state, "CPUID policy hides VMX from a guest profile",
          knhv::FilterCpuid(&policy, 1, 0, &host, &guest) &&
              (guest.ecx & knhv::kCpuidLeaf1EcxVmx) == 0);
    policy = MakeCpuidPolicy();
    const knhv::CpuidResult topology = {1, 2, 3, 4};
    Check(state, "CPUID policy preserves topology only in the native profile",
          knhv::FilterCpuid(&policy, 0xBU, 0, &topology, &guest) &&
              guest.eax == topology.eax);
    policy.flags &= ~knhv::kCpuidPreserveTopology;
    Check(state, "CPUID policy hides topology in an isolated profile",
          knhv::FilterCpuid(&policy, 0xBU, 0, &topology, &guest) &&
              guest.eax == 0 && guest.ebx == 0 && guest.ecx == 0 &&
              guest.edx == 0);
    policy = MakeCpuidPolicy();
    Check(state, "CPUID policy returns a controlled hypervisor leaf",
          knhv::FilterCpuid(&policy, 0x40000000U, 0, &host, &guest) &&
              guest.eax == policy.hypervisor_leaf.eax &&
              guest.ebx == policy.hypervisor_leaf.ebx);
    policy.rules[1].leaf = policy.rules[0].leaf;
    Check(state, "CPUID policy rejects duplicate leaf rules",
          !knhv::IsCpuidPolicyValid(&policy));
}

void CheckMsrPolicy(TestState& state) {
    knhv::MsrPolicy policy = MakeMsrPolicy();
    Check(state, "MSR policy validates explicit actions and masks",
          knhv::IsMsrPolicyValid(&policy));
    knhv::MsrDecision decision = {};
    Check(state, "virtualized TSC reads are masked by policy",
          knhv::EvaluateMsrAccess(&policy, knhv::kMsrIa32Tsc, false,
                                  ~0ULL, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::MsrDecisionStatus::Success) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::MsrAction::Virtualized) &&
              decision.value == ~0ULL);
    Check(state, "virtualized TSC writes reject bits outside the mask",
          knhv::EvaluateMsrAccess(&policy, knhv::kMsrIa32Tsc, true,
                                  1ULL << 60, &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::MsrDecisionStatus::InjectGeneralProtection));
    Check(state, "explicit safe MSR pass-through is preserved",
          knhv::EvaluateMsrAccess(&policy, knhv::kMsrFsBase, false, 0x1234,
                                  &decision) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::MsrAction::PassThrough) &&
              decision.value == 0x1234);
    Check(state, "unknown MSRs inject general protection",
          knhv::EvaluateMsrAccess(&policy, 0xDEADU, false, 0, &decision) &&
              decision.action == static_cast<std::uint32_t>(
                                      knhv::MsrAction::InjectGeneralProtection));
    Check(state, "sensitive EFER writes remain blocked",
          knhv::EvaluateMsrAccess(&policy, knhv::kMsrIa32Efer, true, 0,
                                  &decision) &&
              decision.status == static_cast<std::uint32_t>(
                                      knhv::MsrDecisionStatus::InjectGeneralProtection));
    policy.rules[1].msr = policy.rules[0].msr;
    Check(state, "MSR policy rejects duplicate MSR rules",
          !knhv::IsMsrPolicyValid(&policy));
    policy = MakeMsrPolicy();
    policy.version = knhv::kCpuPolicyContractVersion + 1U;
    Check(state, "MSR policy rejects a future version",
          !knhv::IsMsrPolicyValid(&policy));
}

}  // namespace

void RunCpuPolicyModelContract(TestState& state) {
    CheckCpuidPolicy(state);
    CheckMsrPolicy(state);
}

}  // namespace knhv_tests
