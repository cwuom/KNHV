#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kVmxCapabilityContractVersion = 1U;
constexpr u32 kVmxCapabilityMaxStructSize = 4096U;
constexpr u32 kVmxCapabilityMaxProcessors = 4096U;

// vmx control MSRs use a pair of 32-bit mandatory-one and allowed-one masks
enum class VmxControlEncoding : u32 {
    Pair32 = 1U,
    AllowedOne64 = 2U,
};

constexpr u32 kVmxCapabilitySampleCollected = 1U << 0;
constexpr u32 kVmxCapabilitySampleMsrReadFailed = 1U << 1;
constexpr u32 kVmxCapabilitySampleOwnerConflict = 1U << 2;
constexpr u32 kVmxCapabilitySampleFeatureControlBlocked = 1U << 3;
constexpr u32 kVmxCapabilityKnownSampleStatusMask =
    kVmxCapabilitySampleCollected | kVmxCapabilitySampleMsrReadFailed |
    kVmxCapabilitySampleOwnerConflict |
    kVmxCapabilitySampleFeatureControlBlocked;

constexpr u64 kVmxFeatureVmx = 1ULL << 0;
constexpr u64 kVmxFeatureTrueControls = 1ULL << 1;
constexpr u64 kVmxFeatureSecondaryControls = 1ULL << 2;
constexpr u64 kVmxFeatureTertiaryControls = 1ULL << 3;
constexpr u64 kVmxFeatureEpt = 1ULL << 4;
constexpr u64 kVmxFeatureVpid = 1ULL << 5;
constexpr u64 kVmxFeatureInvept = 1ULL << 6;
constexpr u64 kVmxFeatureInvvpid = 1ULL << 7;
constexpr u64 kVmxFeatureTscScaling = 1ULL << 8;
constexpr u64 kVmxFeatureControlReady = 1ULL << 9;
constexpr u64 kVmxCapabilityKnownFeatureMask = (1ULL << 10) - 1ULL;

constexpr u32 kVmxMatrixAllVmx = 1U << 0;
constexpr u32 kVmxMatrixIdentityUniform = 1U << 1;
constexpr u32 kVmxMatrixSamplesComplete = 1U << 2;
constexpr u32 kVmxMatrixHasInvalidSamples = 1U << 3;
constexpr u32 kVmxMatrixKnownFlagMask =
    kVmxMatrixAllVmx | kVmxMatrixIdentityUniform |
    kVmxMatrixSamplesComplete | kVmxMatrixHasInvalidSamples;

enum class VmxCapabilityMatrixState : u32 {
    Empty = 0,
    CompleteUniform = 1,
    CompleteMixed = 2,
    Incomplete = 3,
    Invalid = 4,
};

// primary and secondary controls used by the dependency checks below
constexpr u32 kVmxPrimaryActivateTertiary = 1U << 17;
constexpr u32 kVmxPrimaryActivateSecondary = 1U << 31;
constexpr u32 kVmxSecondaryEnableEpt = 1U << 1;
constexpr u32 kVmxSecondaryEnableVpid = 1U << 5;
constexpr u32 kVmxSecondaryEnableTscScaling = 1U << 25;

// IA32_VMX_EPT_VPID_CAP bits used by the default hardware profile
constexpr u64 kVmxEptVpidCapEptFourLevel = 1ULL << 6;
constexpr u64 kVmxEptVpidCapEptWriteBack = 1ULL << 14;
constexpr u64 kVmxEptVpidCapInvept = 1ULL << 20;
constexpr u64 kVmxEptVpidCapInveptSingleContext = 1ULL << 25;
constexpr u64 kVmxEptVpidCapInveptAllContext = 1ULL << 26;
constexpr u64 kVmxEptVpidCapInvvpid = 1ULL << 32;
constexpr u64 kVmxEptVpidCapInvvpidIndividualAddress = 1ULL << 40;
constexpr u64 kVmxEptVpidCapInvvpidSingleContext = 1ULL << 41;
constexpr u64 kVmxEptVpidCapInvvpidAllContext = 1ULL << 42;
constexpr u64 kVmxEptVpidCapInvvpidRetainGlobals = 1ULL << 43;
constexpr u64 kVmxEptVpidCapBasicEpt =
    kVmxEptVpidCapEptFourLevel | kVmxEptVpidCapEptWriteBack;

constexpr u64 kVmxEptVpidCapFullInvept =
    kVmxEptVpidCapInvept | kVmxEptVpidCapInveptSingleContext |
    kVmxEptVpidCapInveptAllContext;
constexpr u64 kVmxEptVpidCapFullInvvpid =
    kVmxEptVpidCapInvvpid | kVmxEptVpidCapInvvpidIndividualAddress |
    kVmxEptVpidCapInvvpidSingleContext |
    kVmxEptVpidCapInvvpidAllContext |
    kVmxEptVpidCapInvvpidRetainGlobals;

constexpr u64 kVmxBasicTrueControls = 1ULL << 55;
constexpr u64 kVmxBasicRevisionMask = 0x7FFFFFFFULL;
constexpr u64 kVmxFeatureControlLock = 1ULL << 0;
constexpr u64 kVmxFeatureControlVmxonOutsideSmx = 1ULL << 2;

#pragma pack(push, 8)

struct VmxControlCapability {
    u32 size;
    u32 version;
    u32 encoding;
    u32 reserved;
    u64 mandatory_one;
    u64 allowed_one;
};

struct VmxCapabilitySample {
    u32 size;
    u32 version;
    u32 logical_index;
    u32 processor_group;
    u32 processor_number;
    u32 status;
    u32 reserved0;
    u32 reserved1;
    u64 generation;
    u64 vmx_basic;
    u64 feature_control;
    u64 ept_vpid_cap;
    VmxControlCapability pin_controls;
    VmxControlCapability primary_controls;
    VmxControlCapability secondary_controls;
    VmxControlCapability tertiary_controls;
    VmxControlCapability exit_controls;
    VmxControlCapability entry_controls;
    u64 cr0_fixed0;
    u64 cr0_fixed1;
    u64 cr4_fixed0;
    u64 cr4_fixed1;
    u32 reserved[2];
};

struct VmxControlSet {
    u32 size;
    u32 version;
    u32 pin_controls;
    u32 primary_controls;
    u32 secondary_controls;
    u32 exit_controls;
    u32 entry_controls;
    u64 tertiary_controls;
};

struct VmxCapabilityMatrix {
    u32 size;
    u32 version;
    u32 state;
    u32 flags;
    u32 expected_count;
    u32 sample_count;
    u32 valid_count;
    u32 invalid_count;
    u64 feature_intersection;
    u64 feature_union;
    u64 inconsistent_features;
    u64 ept_vpid_intersection;
    u64 ept_vpid_union;
    u64 generation;
    u32 reserved[4];
};

#pragma pack(pop)

bool IsVmxControlCapabilityValid(const VmxControlCapability* capability);
bool IsVmxControlValueAllowed(const VmxControlCapability* capability,
                              u64 value);
bool NormalizeVmxControlValue(const VmxControlCapability* capability,
                              u64 requested, u64* normalized);

bool IsVmxCapabilitySampleValid(const VmxCapabilitySample* sample);
bool IsVmxCapabilitySampleUsable(const VmxCapabilitySample* sample);
u64 GetVmxCapabilityFeatureFlags(const VmxCapabilitySample* sample);

bool NormalizeVmxControlSet(const VmxCapabilitySample* sample,
                            const VmxControlSet* requested,
                            VmxControlSet* normalized);

bool BuildVmxCapabilityMatrix(const VmxCapabilitySample* samples,
                              u32 sample_count, u32 expected_count,
                              VmxCapabilityMatrix* matrix);
bool IsVmxCapabilityMatrixValid(const VmxCapabilityMatrix* matrix);
bool IsVmxCapabilityMatrixUniform(const VmxCapabilityMatrix* matrix,
                                  u64 required_features,
                                  u64 required_ept_vpid_caps);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::VmxControlCapability) == 32,
              "VMX control capability ABI changed");
static_assert(sizeof(knhv::VmxCapabilitySample) == 296,
              "VMX capability sample ABI changed");
static_assert(sizeof(knhv::VmxControlSet) == 40,
              "VMX control set ABI changed");
static_assert(sizeof(knhv::VmxCapabilityMatrix) == 96,
              "VMX capability matrix ABI changed");
#endif
