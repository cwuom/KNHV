#include "knhv_boot_contract.h"

namespace knhv {
namespace {

bool ValidContext(const BootContext* context) {
    return context != nullptr &&
           IsVersionedBufferValid(context->version, context->size,
                                  sizeof(BootContext)) &&
           context->reserved == 0 && context->logical_processors != 0 &&
           context->logical_processors <= 4096U;
}

bool ValidContract(const BootL0Contract* contract) {
    return contract != nullptr &&
           IsVersionedBufferValid(contract->version, contract->size,
                                  sizeof(BootL0Contract));
}

void PublishEvidence(BootL0Contract* contract, HvStatus status) {
    contract->evidence.version = kAbiVersion;
    contract->evidence.size = sizeof(BootEvidence);
    contract->evidence.state = contract->state;
    contract->evidence.boot_generation = contract->generation;
    contract->evidence.owner_generation = contract->owner.generation;
    contract->evidence.owner_count = contract->owner.owner_count;
    contract->evidence.active_processors = contract->owner.active_processors;
    contract->evidence.last_status = status;
}

void InvalidateOwner(BootL0Contract* contract) {
    contract->owner.nonce = 0;
    contract->owner.generation = 0;
    contract->owner.owner_count = 0;
    contract->owner.active_processors = 0;
    contract->owner.reserved = 0;
}

}  // namespace

void InitializeBootL0Contract(BootL0Contract* contract) {
    if (contract == nullptr) return;
    *contract = {};
    contract->version = kAbiVersion;
    contract->size = sizeof(BootL0Contract);
    contract->state = BootL0State::PreL0;
    contract->generation = 1U;
    InvalidateOwner(contract);
    PublishEvidence(contract, HvStatus::Success);
}

HvStatus StartBootL0(BootL0Contract* contract, const BootContext* context) {
    if (!ValidContract(contract) || !ValidContext(context)) {
        return HvStatus::InvalidParameter;
    }
    if (contract->state == BootL0State::RootActive ||
        contract->state == BootL0State::WindowsHandoff ||
        contract->state == BootL0State::Ready) {
        PublishEvidence(contract, HvStatus::Busy);
        return HvStatus::Busy;
    }
    if (context->external_owner != 0) {
        contract->state = BootL0State::Recovery;
        InvalidateOwner(contract);
        PublishEvidence(contract, HvStatus::HardwareOwnerConflict);
        return HvStatus::HardwareOwnerConflict;
    }
    if (context->manifest_valid == 0 || context->physical_vmx_ready == 0) {
        contract->state = BootL0State::Recovery;
        InvalidateOwner(contract);
        const HvStatus status = context->manifest_valid == 0
                                    ? HvStatus::BootHandoffFailed
                                    : HvStatus::HardwareUnsupported;
        PublishEvidence(contract, status);
        return status;
    }
    ++contract->generation;
    if (contract->generation == 0) contract->generation = 1U;
    contract->state = BootL0State::RootActive;
    contract->owner.nonce =
        (static_cast<u64>(contract->generation) << 32) |
        static_cast<u64>(context->logical_processors);
    contract->owner.generation = contract->generation;
    contract->owner.owner_count = 1U;
    contract->owner.active_processors = context->logical_processors;
    contract->owner.reserved = 0;
    PublishEvidence(contract, HvStatus::Success);
    return HvStatus::Success;
}

HvStatus HandoffWindows(BootL0Contract* contract, const BootContext* context) {
    if (!ValidContract(contract) || !ValidContext(context)) {
        return HvStatus::InvalidParameter;
    }
    if (contract->state != BootL0State::RootActive ||
        contract->owner.owner_count != 1U ||
        contract->owner.active_processors != context->logical_processors) {
        PublishEvidence(contract, HvStatus::RecoveryRequired);
        return HvStatus::RecoveryRequired;
    }
    if (context->windows_handoff_ready == 0) {
        contract->state = BootL0State::Recovery;
        InvalidateOwner(contract);
        PublishEvidence(contract, HvStatus::BootHandoffFailed);
        return HvStatus::BootHandoffFailed;
    }
    contract->state = BootL0State::WindowsHandoff;
    PublishEvidence(contract, HvStatus::Success);
    contract->state = BootL0State::Ready;
    PublishEvidence(contract, HvStatus::Success);
    return HvStatus::Success;
}

HvStatus RecoverBootL0(BootL0Contract* contract, HvStatus reason) {
    if (!ValidContract(contract)) return HvStatus::InvalidParameter;
    contract->state = BootL0State::Recovery;
    InvalidateOwner(contract);
    PublishEvidence(contract, reason == HvStatus::Success
                                  ? HvStatus::RecoveryRequired
                                  : reason);
    return contract->evidence.last_status;
}

HvStatus StopBootL0(BootL0Contract* contract) {
    if (!ValidContract(contract)) return HvStatus::InvalidParameter;
    if (contract->state != BootL0State::Ready &&
        contract->state != BootL0State::RootActive &&
        contract->state != BootL0State::WindowsHandoff) {
        return contract->state == BootL0State::PreL0 ? HvStatus::Success
                                                      : HvStatus::RecoveryRequired;
    }
    InvalidateOwner(contract);
    contract->state = BootL0State::PreL0;
    PublishEvidence(contract, HvStatus::Success);
    return HvStatus::Success;
}

}  // namespace knhv
