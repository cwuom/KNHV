#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kOwnerObservationContractVersion = 1U;
constexpr u32 kOwnerObservationMaxStructSize = 4096U;

// each probe source records whether it was unavailable, clear, or observed
enum class OwnerEvidenceState : u32 {
    Unknown = 0,
    Clear = 1,
    Present = 2,
};

// native acquisition requires an explicit action rather than a guessed owner
enum class OwnerGateAction : u32 {
    Block = 0,
    AcquireNative = 1,
    UseExternalProvider = 2,
    UseWhp = 3,
    UseSynthetic = 4,
};

enum class OwnerGateReason : u32 {
    None = 0,
    InvalidObservation = 1,
    UnknownOwner = 2,
    ContradictoryEvidence = 3,
    WindowsHypervisorActive = 4,
    VbsActive = 5,
    HvciActive = 6,
    ExternalOwnerActive = 7,
    KnhvHandoffMissing = 8,
    KnhvOwnerReady = 9,
    WhpFallback = 10,
    SyntheticFallback = 11,
    ProviderUnavailable = 12,
    GenerationMissing = 13,
    ProviderStateInvalid = 14,
};

constexpr u32 kOwnerGateFlagEvidenceComplete = 1U << 0;
constexpr u32 kOwnerGateFlagExclusive = 1U << 1;
constexpr u32 kOwnerGateFlagFallback = 1U << 2;
constexpr u32 kOwnerGateFlagConflict = 1U << 3;
constexpr u32 kOwnerGateKnownFlagMask =
    kOwnerGateFlagEvidenceComplete | kOwnerGateFlagExclusive |
    kOwnerGateFlagFallback | kOwnerGateFlagConflict;

#pragma pack(push, 8)

struct OwnerObservation {
    u32 size;
    u32 version;
    u32 cpuid_hypervisor;
    u32 windows_hypervisor;
    u32 vbs;
    u32 hvci;
    u32 whp_available;
    u32 provider_device;
    u32 boot_handoff;
    u32 provider_owner;
    u32 provider_state;
    u32 reserved;
    u64 generation;
};

struct OwnerGateResult {
    u32 size;
    u32 version;
    u32 action;
    u32 reason;
    HvStatus status;
    u32 owner;
    u32 flags;
    u32 reserved;
    u64 generation;
};

#pragma pack(pop)

bool IsOwnerObservationValid(const OwnerObservation* observation);
bool EvaluateOwnerGate(const OwnerObservation* observation,
                       OwnerGateResult* result);
bool IsOwnerGateResultValid(const OwnerGateResult* result);

const char* OwnerGateActionText(OwnerGateAction action);
const char* OwnerGateReasonText(OwnerGateReason reason);
const char* OwnerKindText(HvOwnerKindV2 owner);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::OwnerObservation) == 56,
              "owner observation ABI changed");
static_assert(sizeof(knhv::OwnerGateResult) == 40,
              "owner gate result ABI changed");
#endif
