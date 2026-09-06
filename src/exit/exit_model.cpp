#include "knhv_exit.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kExitContractVersion && size >= required &&
           size <= kExitMaxStructSize;
}

bool IsLinearBitsValid(u32 bits) {
    return bits >= 48U && bits <= 63U;
}

bool IsPhysicalBitsValid(u32 bits) {
    return bits >= 12U && bits <= 52U;
}

bool IsCanonical(u64 value, u32 bits) {
    if (!IsLinearBitsValid(bits)) return false;
    const u64 low_mask = (1ULL << bits) - 1ULL;
    const u64 sign_bit = 1ULL << (bits - 1U);
    const u64 upper = value & ~low_mask;
    return (value & sign_bit) == 0 ? upper == 0 : upper == ~low_mask;
}

u32 ClassBit(ExitClass exit_class) {
    switch (exit_class) {
        case ExitClass::Interrupt:
            return kExitClassInterrupt;
        case ExitClass::NestedVmx:
            return kExitClassNestedVmx;
        case ExitClass::CpuControl:
            return kExitClassCpuControl;
        case ExitClass::Time:
            return kExitClassTime;
        case ExitClass::Msr:
            return kExitClassMsr;
        case ExitClass::Io:
            return kExitClassIo;
        case ExitClass::Memory:
            return kExitClassMemory;
        case ExitClass::GuestState:
            return kExitClassGuestState;
        case ExitClass::Fatal:
            return kExitClassFatal;
        default:
            return 0;
    }
}

bool IsVmInstructionReason(u32 reason) {
    return reason >= static_cast<u32>(ExitReason::Vmcall) &&
           reason <= static_cast<u32>(ExitReason::Vmxon);
}

bool PolicyHandlesClass(const ExitPolicy& policy, ExitClass exit_class) {
    return (policy.allowed_classes & ClassBit(exit_class)) != 0;
}

void InitializeDecision(const ExitRecord* record, ExitDecision* decision) {
    *decision = {};
    decision->size = sizeof(*decision);
    decision->version = kExitContractVersion;
    decision->reason = record == nullptr ? 0U : record->reason;
    decision->instruction_length =
        record == nullptr ? 0U : record->instruction_length;
    decision->generation = record == nullptr ? 0 : record->generation;
}

void SetDecision(ExitDecision* decision, ExitDecisionStatus status,
                 ExitAction action, u32 exception_vector) {
    decision->status = static_cast<u32>(status);
    decision->action = static_cast<u32>(action);
    decision->exception_vector = exception_vector;
}

}  // namespace

ExitClass ClassifyExitReason(u32 reason) {
    switch (static_cast<ExitReason>(reason)) {
        case ExitReason::ExceptionOrNmi:
        case ExitReason::ExternalInterrupt:
        case ExitReason::InterruptWindow:
        case ExitReason::NmiWindow:
            return ExitClass::Interrupt;
        case ExitReason::Vmcall:
        case ExitReason::Vmclear:
        case ExitReason::Vmlaunch:
        case ExitReason::Vmptrld:
        case ExitReason::Vmptrst:
        case ExitReason::Vmread:
        case ExitReason::Vmresume:
        case ExitReason::Vmwrite:
        case ExitReason::Vmxoff:
        case ExitReason::Vmxon:
        case ExitReason::Invept:
        case ExitReason::Invvpid:
        case ExitReason::Vmfunc:
            return ExitClass::NestedVmx;
        case ExitReason::Hlt:
        case ExitReason::Cpuid:
        case ExitReason::Invlpg:
        case ExitReason::Rdpmc:
        case ExitReason::CrAccess:
        case ExitReason::Mwait:
        case ExitReason::MonitorTrap:
        case ExitReason::Monitor:
        case ExitReason::Pause:
        case ExitReason::ApicWrite:
        case ExitReason::Invpcid:
        case ExitReason::Xsetbv:
            return ExitClass::CpuControl;
        case ExitReason::Rdtsc:
        case ExitReason::Rdtscp:
            return ExitClass::Time;
        case ExitReason::Rdmsr:
        case ExitReason::Wrmsr:
        case ExitReason::Xsaves:
        case ExitReason::Xrstors:
            return ExitClass::Msr;
        case ExitReason::IoInstruction:
            return ExitClass::Io;
        case ExitReason::EptViolation:
        case ExitReason::EptMisconfiguration:
            return ExitClass::Memory;
        case ExitReason::InvalidGuestState:
        case ExitReason::MsrLoading:
            return ExitClass::GuestState;
        case ExitReason::TripleFault:
        case ExitReason::MachineCheck:
            return ExitClass::Fatal;
        default:
            return ExitClass::Unknown;
    }
}

bool IsExitPolicyValid(const ExitPolicy* policy, u32 linear_address_bits) {
    if (policy == nullptr ||
        !IsVersionedSizeValid(policy->version, policy->size,
                              sizeof(ExitPolicy)) ||
        (policy->level != 1U && policy->level != 2U) ||
        (policy->flags & ~kExitKnownPolicyMask) != 0 ||
        (policy->allowed_classes & ~kExitKnownClassMask) != 0 ||
        policy->max_instruction_length == 0 ||
        policy->max_instruction_length > kExitMaxInstructionLength ||
        policy->generation == 0 || policy->reserved != 0 ||
        !IsLinearBitsValid(linear_address_bits)) {
        return false;
    }
    if ((policy->flags & kExitPolicyVirtualizeTsc) != 0 &&
        (policy->allowed_classes & kExitClassTime) == 0) {
        return false;
    }
    if ((policy->flags & kExitPolicyVirtualizeCpuid) != 0 &&
        (policy->allowed_classes & kExitClassCpuControl) == 0) {
        return false;
    }
    if ((policy->flags & kExitPolicyVirtualizeMsr) != 0 &&
        (policy->allowed_classes & kExitClassMsr) == 0) {
        return false;
    }
    if ((policy->flags & kExitPolicyAllowIo) != 0 &&
        (policy->allowed_classes & kExitClassIo) == 0) {
        return false;
    }
    if ((policy->flags & kExitPolicyReflectVmx) != 0 &&
        (policy->allowed_classes & kExitClassNestedVmx) == 0) {
        return false;
    }
    if ((policy->flags & kExitPolicyReflectEpt) != 0 &&
        (policy->allowed_classes & kExitClassMemory) == 0) {
        return false;
    }
    return true;
}

bool IsExitRecordValid(const ExitRecord* record, u32 physical_address_bits,
                       u32 linear_address_bits) {
    return record != nullptr &&
           IsVersionedSizeValid(record->version, record->size,
                                sizeof(ExitRecord)) &&
           record->reason <= 0xFFFFU &&
           record->instruction_length <= kExitMaxInstructionLength &&
           (record->flags & ~kExitKnownRecordMask) == 0 &&
           record->reserved == 0 && record->generation != 0 &&
           IsPhysicalBitsValid(physical_address_bits) &&
           IsLinearBitsValid(linear_address_bits) &&
           (record->guest_physical >> physical_address_bits) == 0 &&
           IsCanonical(record->guest_linear, linear_address_bits) &&
           IsCanonical(record->guest_rip, linear_address_bits);
}

bool EvaluateExit(const ExitRecord* record, const ExitPolicy* policy,
                  u32 physical_address_bits, u32 linear_address_bits,
                  ExitDecision* decision) {
    if (decision == nullptr) return false;
    InitializeDecision(record, decision);
    if (!IsExitRecordValid(record, physical_address_bits, linear_address_bits) ||
        !IsExitPolicyValid(policy, linear_address_bits)) {
        SetDecision(decision, ExitDecisionStatus::InvalidParameter,
                    ExitAction::QuarantineVcpu, 0);
        return false;
    }
    if (record->generation != policy->generation) {
        SetDecision(decision, ExitDecisionStatus::GenerationMismatch,
                    ExitAction::QuarantineVcpu, 0);
        return true;
    }
    if (record->instruction_length > policy->max_instruction_length) {
        SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                    ExitAction::QuarantineVcpu, 0);
        return true;
    }

    const ExitClass exit_class = ClassifyExitReason(record->reason);
    if (exit_class == ExitClass::Unknown) {
        SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                    ExitAction::QuarantineVcpu, 0);
        return true;
    }
    if ((record->flags & kExitRecordEntryFailure) != 0 &&
        exit_class != ExitClass::GuestState) {
        SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                    ExitAction::QuarantineVcpu, 0);
        return true;
    }
    if (exit_class == ExitClass::Memory &&
        (record->flags & kExitRecordHostOwned) != 0) {
        SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                    ExitAction::QuarantineVcpu, 0);
        return true;
    }
    if (record->reason == static_cast<u32>(ExitReason::EptMisconfiguration) ||
        record->reason == static_cast<u32>(ExitReason::MachineCheck)) {
        SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                    ExitAction::FatalHost, 0);
        return true;
    }
    if (exit_class == ExitClass::NestedVmx) {
        if ((policy->flags & kExitPolicyReflectVmx) != 0 &&
            PolicyHandlesClass(*policy, exit_class)) {
            SetDecision(decision, ExitDecisionStatus::Success,
                        ExitAction::ReflectToL1, 0);
        } else {
            SetDecision(decision, ExitDecisionStatus::UnsupportedReason,
                        ExitAction::InjectUndefinedInstruction, 6U);
        }
        return true;
    }
    if (exit_class == ExitClass::Interrupt) {
        SetDecision(decision, ExitDecisionStatus::Success,
                    ExitAction::ResumeGuest, 0);
        return true;
    }
    if (exit_class == ExitClass::Fatal) {
        if (record->reason == static_cast<u32>(ExitReason::TripleFault) &&
            PolicyHandlesClass(*policy, exit_class)) {
            SetDecision(decision, ExitDecisionStatus::Success,
                        ExitAction::ReflectToL1, 0);
        } else {
            SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                        ExitAction::QuarantineVcpu, 0);
        }
        return true;
    }
    bool locally_handled = false;
    if (record->reason == static_cast<u32>(ExitReason::Cpuid)) {
        locally_handled =
            (policy->flags & kExitPolicyVirtualizeCpuid) != 0;
    } else if (exit_class == ExitClass::Time) {
        locally_handled =
            (policy->flags & kExitPolicyVirtualizeTsc) != 0;
    } else if (exit_class == ExitClass::Msr) {
        locally_handled =
            (policy->flags & kExitPolicyVirtualizeMsr) != 0;
    } else if (exit_class == ExitClass::Io) {
        locally_handled = (policy->flags & kExitPolicyAllowIo) != 0;
    } else if (exit_class == ExitClass::Memory) {
        locally_handled = (policy->flags & kExitPolicyReflectEpt) != 0;
    } else if (exit_class == ExitClass::CpuControl) {
        locally_handled = true;
    }
    if (locally_handled && PolicyHandlesClass(*policy, exit_class)) {
        SetDecision(decision, ExitDecisionStatus::Success,
                    exit_class == ExitClass::Memory
                        ? ExitAction::ReflectToL1
                        : ExitAction::ResumeGuest,
                    0);
        return true;
    }
    if (PolicyHandlesClass(*policy, exit_class)) {
        SetDecision(decision, ExitDecisionStatus::Success,
                    ExitAction::ReflectToL1, 0);
        return true;
    }
    if (IsVmInstructionReason(record->reason)) {
        SetDecision(decision, ExitDecisionStatus::UnsupportedReason,
                    ExitAction::InjectUndefinedInstruction, 6U);
        return true;
    }
    SetDecision(decision, ExitDecisionStatus::QuarantineRequired,
                ExitAction::QuarantineVcpu, 0);
    return true;
}

}  // namespace knhv
