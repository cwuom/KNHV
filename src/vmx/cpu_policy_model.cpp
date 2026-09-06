#include "knhv_cpu_policy.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kCpuPolicyContractVersion && size >= required &&
           size <= kCpuPolicyMaxStructSize;
}

bool IsLevelValid(u32 level) { return level == 1U || level == 2U; }

bool IsMsrActionValid(u32 action) {
    return action <= static_cast<u32>(MsrAction::InjectUndefinedInstruction);
}

bool IsSpecialPassThroughAllowed(const MsrPolicy& policy, u32 msr) {
    if ((policy.flags & kMsrPolicyAllowPassThrough) == 0) return false;
    if (msr == kMsrIa32Tsc) {
        return (policy.flags & kMsrPolicyAllowTsc) != 0;
    }
    if (msr == kMsrIa32Pat) {
        return (policy.flags & kMsrPolicyAllowPat) != 0;
    }
    if (msr == kMsrIa32Debugctl) {
        return (policy.flags & kMsrPolicyAllowDebug) != 0;
    }
    if (msr == kMsrIa32Xss || msr == kMsrIa32UCet ||
        msr == kMsrIa32SCet) {
        return (policy.flags & kMsrPolicyAllowCet) != 0;
    }
    return msr != kMsrIa32Efer;
}

const MsrRule* FindMsrRule(const MsrPolicy& policy, u32 msr) {
    for (u32 index = 0; index < policy.rule_count; ++index) {
        if (policy.rules[index].msr == msr) return &policy.rules[index];
    }
    return nullptr;
}

void ClearCpuid(CpuidResult* result) {
    if (result != nullptr) *result = {};
}

void InitializeMsrDecision(u32 msr, bool write, u64 generation,
                           MsrDecision* decision) {
    *decision = {};
    decision->size = sizeof(*decision);
    decision->version = kCpuPolicyContractVersion;
    decision->msr = msr;
    decision->access = write ? kMsrAccessWrite : kMsrAccessRead;
    decision->generation = generation;
}

void SetMsrDecision(MsrDecision* decision, MsrDecisionStatus status,
                    MsrAction action, u64 value) {
    decision->status = static_cast<u32>(status);
    decision->action = static_cast<u32>(action);
    decision->value = value;
}

}  // namespace

bool IsCpuidPolicyValid(const CpuidPolicy* policy) {
    if (policy == nullptr ||
        !IsVersionedSizeValid(policy->version, policy->size,
                              sizeof(CpuidPolicy)) ||
        !IsLevelValid(policy->level) ||
        (policy->flags & ~kCpuidKnownPolicyMask) != 0 ||
        policy->rule_count > kCpuPolicyMaxCpuidRules || policy->reserved != 0 ||
        policy->generation == 0 || policy->max_basic_leaf == 0 ||
        policy->max_basic_leaf >= 0x80000000U ||
        policy->max_extended_leaf < 0x80000000U || policy->reserved2 != 0 ||
        policy->reserved3 != 0) {
        return false;
    }
    if ((policy->flags & kCpuidExposeHypervisor) != 0) {
        if (policy->hypervisor_leaf.eax < 0x40000000U) return false;
    } else if (policy->hypervisor_leaf.eax != 0 ||
               policy->hypervisor_leaf.ebx != 0 ||
               policy->hypervisor_leaf.ecx != 0 ||
               policy->hypervisor_leaf.edx != 0) {
        return false;
    }
    for (u32 index = 0; index < policy->rule_count; ++index) {
        const CpuidRule& rule = policy->rules[index];
        if (rule.reserved != 0 || rule.reserved2 != 0 ||
            (rule.leaf >= 0x40000000U && rule.leaf < 0x80000000U)) {
            return false;
        }
        for (u32 prior = 0; prior < index; ++prior) {
            if (policy->rules[prior].leaf == rule.leaf &&
                policy->rules[prior].subleaf == rule.subleaf) {
                return false;
            }
        }
    }
    for (u32 index = policy->rule_count; index < kCpuPolicyMaxCpuidRules;
         ++index) {
        if (policy->rules[index].leaf != 0 ||
            policy->rules[index].subleaf != 0 ||
            policy->rules[index].eax_and != 0 ||
            policy->rules[index].ebx_and != 0 ||
            policy->rules[index].ecx_and != 0 ||
            policy->rules[index].edx_and != 0 ||
            policy->rules[index].reserved != 0 ||
            policy->rules[index].reserved2 != 0) {
            return false;
        }
    }
    return true;
}

bool FilterCpuid(const CpuidPolicy* policy, u32 leaf, u32 subleaf,
                 const CpuidResult* host, CpuidResult* guest) {
    if (guest == nullptr || host == nullptr || !IsCpuidPolicyValid(policy)) {
        return false;
    }
    ClearCpuid(guest);
    if (leaf == 0x40000000U) {
        if ((policy->flags & kCpuidExposeHypervisor) != 0) {
            *guest = policy->hypervisor_leaf;
        }
        return true;
    }
    if (leaf < 0x80000000U) {
        if (leaf > policy->max_basic_leaf) return true;
    } else if (leaf > policy->max_extended_leaf) {
        return true;
    }
    *guest = *host;
    if (leaf == 0U) {
        if (guest->eax > policy->max_basic_leaf) {
            guest->eax = policy->max_basic_leaf;
        }
    } else if (leaf == 0x80000000U &&
               guest->eax > policy->max_extended_leaf) {
        guest->eax = policy->max_extended_leaf;
    }
    for (u32 index = 0; index < policy->rule_count; ++index) {
        const CpuidRule& rule = policy->rules[index];
        if (rule.leaf == leaf && rule.subleaf == subleaf) {
            guest->eax &= rule.eax_and;
            guest->ebx &= rule.ebx_and;
            guest->ecx &= rule.ecx_and;
            guest->edx &= rule.edx_and;
            break;
        }
    }
    if (leaf == 1U) {
        if ((policy->flags & kCpuidExposeVmx) != 0 &&
            (host->ecx & kCpuidLeaf1EcxVmx) != 0) {
            guest->ecx |= kCpuidLeaf1EcxVmx;
        } else {
            guest->ecx &= ~kCpuidLeaf1EcxVmx;
        }
        if ((policy->flags & kCpuidExposeHypervisor) != 0) {
            guest->ecx |= kCpuidLeaf1EcxHypervisor;
        } else {
            guest->ecx &= ~kCpuidLeaf1EcxHypervisor;
        }
    }
    if (leaf == 0x80000007U &&
        (policy->flags & kCpuidExposeInvariantTsc) == 0) {
        guest->edx &= ~kCpuidLeaf80000007EdxInvariantTsc;
    }
    if ((leaf == 0xBU || leaf == 0x1FU) &&
        (policy->flags & kCpuidPreserveTopology) == 0) {
        ClearCpuid(guest);
    }
    return true;
}

bool IsMsrPolicyValid(const MsrPolicy* policy) {
    if (policy == nullptr ||
        !IsVersionedSizeValid(policy->version, policy->size,
                              sizeof(MsrPolicy)) ||
        !IsLevelValid(policy->level) ||
        (policy->flags & ~kMsrPolicyKnownMask) != 0 ||
        policy->rule_count > kCpuPolicyMaxMsrRules || policy->reserved != 0 ||
        policy->generation == 0) {
        return false;
    }
    for (u32 index = 0; index < policy->rule_count; ++index) {
        const MsrRule& rule = policy->rules[index];
        if (!IsMsrActionValid(rule.read_action) ||
            !IsMsrActionValid(rule.write_action) || rule.reserved != 0 ||
            rule.reserved2 != 0 ||
            (rule.write_required_one & ~rule.write_allowed_mask) != 0) {
            return false;
        }
        if (rule.read_action ==
                static_cast<u32>(MsrAction::InjectGeneralProtection) ||
            rule.read_action ==
                static_cast<u32>(MsrAction::InjectUndefinedInstruction)) {
            if (rule.read_mask != 0) return false;
        }
        if (rule.write_action ==
                static_cast<u32>(MsrAction::InjectGeneralProtection) ||
            rule.write_action ==
                static_cast<u32>(MsrAction::InjectUndefinedInstruction)) {
            if (rule.write_allowed_mask != 0 || rule.write_required_one != 0) {
                return false;
            }
        }
        if (rule.read_action == static_cast<u32>(MsrAction::PassThrough) &&
            !IsSpecialPassThroughAllowed(*policy, rule.msr)) {
            return false;
        }
        if (rule.write_action == static_cast<u32>(MsrAction::PassThrough) &&
            !IsSpecialPassThroughAllowed(*policy, rule.msr)) {
            return false;
        }
        for (u32 prior = 0; prior < index; ++prior) {
            if (policy->rules[prior].msr == rule.msr) return false;
        }
    }
    for (u32 index = policy->rule_count; index < kCpuPolicyMaxMsrRules;
         ++index) {
        if (policy->rules[index].msr != 0 ||
            policy->rules[index].read_action != 0 ||
            policy->rules[index].write_action != 0 ||
            policy->rules[index].reserved != 0 ||
            policy->rules[index].read_mask != 0 ||
            policy->rules[index].write_allowed_mask != 0 ||
            policy->rules[index].write_required_one != 0 ||
            policy->rules[index].reserved2 != 0) {
            return false;
        }
    }
    return true;
}

bool EvaluateMsrAccess(const MsrPolicy* policy, u32 msr, bool write,
                       u64 value, MsrDecision* decision) {
    if (decision == nullptr) return false;
    InitializeMsrDecision(msr, write, policy == nullptr ? 0 : policy->generation,
                          decision);
    if (!IsMsrPolicyValid(policy)) {
        SetMsrDecision(decision, MsrDecisionStatus::InvalidParameter,
                       MsrAction::InjectGeneralProtection, 0);
        return false;
    }
    const MsrRule* rule = FindMsrRule(*policy, msr);
    if (rule == nullptr) {
        SetMsrDecision(decision, MsrDecisionStatus::InjectGeneralProtection,
                       MsrAction::InjectGeneralProtection, 0);
        return true;
    }
    const u32 action_value = write ? rule->write_action : rule->read_action;
    const auto action = static_cast<MsrAction>(action_value);
    if (action == MsrAction::PassThrough &&
        !IsSpecialPassThroughAllowed(*policy, msr)) {
        SetMsrDecision(decision, MsrDecisionStatus::InjectGeneralProtection,
                       MsrAction::InjectGeneralProtection, 0);
        return true;
    }
    if (action == MsrAction::Virtualized) {
        if (write) {
            if ((value & ~rule->write_allowed_mask) != 0) {
                SetMsrDecision(decision,
                               MsrDecisionStatus::InjectGeneralProtection,
                               MsrAction::InjectGeneralProtection, 0);
                return true;
            }
            value = (value & rule->write_allowed_mask) |
                    rule->write_required_one;
        } else {
            value &= rule->read_mask;
        }
        SetMsrDecision(decision, MsrDecisionStatus::Success, action, value);
        return true;
    }
    if (action == MsrAction::PassThrough) {
        SetMsrDecision(decision, MsrDecisionStatus::Success, action, value);
        return true;
    }
    if (action == MsrAction::InjectUndefinedInstruction) {
        SetMsrDecision(decision,
                       MsrDecisionStatus::InjectUndefinedInstruction, action,
                       0);
        return true;
    }
    SetMsrDecision(decision, MsrDecisionStatus::InjectGeneralProtection, action,
                   0);
    return true;
}

}  // namespace knhv
