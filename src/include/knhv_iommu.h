#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kIommuContractVersion = 1U;
constexpr u32 kIommuMaxStructSize = 4096U;
constexpr u32 kIommuPageSize = 4096U;
constexpr u32 kIommuPageShift = 12U;
constexpr u32 kIommuMaxPhysicalAddressBits = 52U;
constexpr u32 kIommuMaxReservedRanges = 4U;
constexpr u32 kIommuMaxMappingPages = 1U << 20;
constexpr u32 kIommuMaxMsixVectors = 2048U;

constexpr u64 kIommuCapQueuedInvalidation = 1ULL << 0;
constexpr u64 kIommuCapInterruptRemapping = 1ULL << 1;
constexpr u64 kIommuCapNestedTranslation = 1ULL << 2;
constexpr u64 kIommuCapAts = 1ULL << 3;
constexpr u64 kIommuCapPri = 1ULL << 4;
constexpr u64 kIommuCapPasid = 1ULL << 5;
constexpr u64 kIommuCapScalableMode = 1ULL << 6;
constexpr u64 kIommuKnownCapabilityMask =
    kIommuCapQueuedInvalidation | kIommuCapInterruptRemapping |
    kIommuCapNestedTranslation | kIommuCapAts | kIommuCapPri |
    kIommuCapPasid | kIommuCapScalableMode;

constexpr u32 kIommuDeviceHostOwned = 1U << 0;
constexpr u32 kIommuDeviceSystemCritical = 1U << 1;
constexpr u32 kIommuDeviceDisplay = 1U << 2;
constexpr u32 kIommuDeviceIsolationComplete = 1U << 3;
constexpr u32 kIommuDeviceResetReliable = 1U << 4;
constexpr u32 kIommuDeviceAllowL1 = 1U << 5;
constexpr u32 kIommuDeviceAllowL2 = 1U << 6;
constexpr u32 kIommuDeviceSriov = 1U << 7;
constexpr u32 kIommuDeviceAts = 1U << 8;
constexpr u32 kIommuDevicePri = 1U << 9;
constexpr u32 kIommuDevicePasid = 1U << 10;
constexpr u32 kIommuDeviceHasRmrr = 1U << 11;
constexpr u32 kIommuDeviceMsix = 1U << 12;
constexpr u32 kIommuKnownDeviceMask =
    kIommuDeviceHostOwned | kIommuDeviceSystemCritical |
    kIommuDeviceDisplay | kIommuDeviceIsolationComplete |
    kIommuDeviceResetReliable | kIommuDeviceAllowL1 | kIommuDeviceAllowL2 |
    kIommuDeviceSriov | kIommuDeviceAts | kIommuDevicePri |
    kIommuDevicePasid | kIommuDeviceHasRmrr | kIommuDeviceMsix;

constexpr u32 kIommuDomainNested = 1U << 0;
constexpr u32 kIommuDomainInterruptRemap = 1U << 1;
constexpr u32 kIommuDomainReadOnly = 1U << 2;
constexpr u32 kIommuDomainIdentity = 1U << 3;
constexpr u32 kIommuKnownDomainMask = kIommuDomainNested |
                                       kIommuDomainInterruptRemap |
                                       kIommuDomainReadOnly |
                                       kIommuDomainIdentity;

constexpr u32 kIommuMappingPresent = 1U << 0;
constexpr u32 kIommuMappingHostOwned = 1U << 1;
constexpr u32 kIommuMappingPinned = 1U << 2;
constexpr u32 kIommuMappingLargePage = 1U << 3;
constexpr u32 kIommuKnownMappingMask =
    kIommuMappingPresent | kIommuMappingHostOwned | kIommuMappingPinned |
    kIommuMappingLargePage;

constexpr u32 kIommuPermissionRead = 1U << 0;
constexpr u32 kIommuPermissionWrite = 1U << 1;
constexpr u32 kIommuKnownPermissionMask =
    kIommuPermissionRead | kIommuPermissionWrite;

constexpr u32 kIommuReadyHostQuiesced = 1U << 0;
constexpr u32 kIommuReadyDmaDrained = 1U << 1;
constexpr u32 kIommuReadyInterruptsDrained = 1U << 2;
constexpr u32 kIommuReadyResetComplete = 1U << 3;
constexpr u32 kIommuKnownReadyMask =
    kIommuReadyHostQuiesced | kIommuReadyDmaDrained |
    kIommuReadyInterruptsDrained | kIommuReadyResetComplete;
constexpr u32 kIommuActivateReadyMask = kIommuReadyHostQuiesced |
                                         kIommuReadyDmaDrained |
                                         kIommuReadyInterruptsDrained |
                                         kIommuReadyResetComplete;
constexpr u32 kIommuDetachReadyMask = kIommuReadyHostQuiesced |
                                       kIommuReadyDmaDrained |
                                       kIommuReadyInterruptsDrained;
constexpr u32 kIommuCompleteDetachReadyMask = kIommuDetachReadyMask |
                                              kIommuReadyResetComplete;

constexpr u32 kIommuAssignmentNested = 1U << 0;
constexpr u32 kIommuAssignmentInterruptRemap = 1U << 1;
constexpr u32 kIommuAssignmentQuarantined = 1U << 2;
constexpr u32 kIommuKnownAssignmentMask =
    kIommuAssignmentNested | kIommuAssignmentInterruptRemap |
    kIommuAssignmentQuarantined;

enum class IommuDomainKind : u32 {
    Host = 1,
    L1 = 2,
    L2 = 3,
    Quarantine = 4,
};

enum class IommuDomainState : u32 {
    Empty = 0,
    Prepared = 1,
    Active = 2,
    Draining = 3,
    Quarantined = 4,
    Retired = 5,
};

enum class IommuResetMethod : u32 {
    None = 0,
    Flr = 1,
    SecondaryBus = 2,
};

enum class IommuDmaAccess : u32 {
    Read = 1,
    Write = 2,
};

enum class IommuLookupStatus : u32 {
    Hit = 0,
    NotPresent = 1,
    PermissionDenied = 2,
    Stale = 3,
    Invalid = 4,
    HostOwned = 5,
    Quarantined = 6,
};

enum class IommuFaultReason : u32 {
    InvalidAddress = 1,
    Permission = 2,
    Translation = 3,
    Interrupt = 4,
    DeviceState = 5,
    Unknown = 6,
};

enum class IommuAssignmentStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    CapabilityMismatch = 2,
    IsolationIncomplete = 3,
    HostOwned = 4,
    CriticalDevice = 5,
    ResetUnsupported = 6,
    GenerationMismatch = 7,
    DomainInvalid = 8,
    AddressInvalid = 9,
    QuiesceRequired = 10,
    StateConflict = 11,
    FaultQuarantined = 12,
};

#pragma pack(push, 8)

struct IommuBdf {
    u16 segment;
    u8 bus;
    u8 device;
    u8 function;
    u8 reserved[3];
};

struct IommuRange {
    u64 base;
    u64 length;
    u32 flags;
    u32 reserved;
};

struct IommuCapabilities {
    u32 size;
    u32 version;
    u64 feature_flags;
    u32 max_physical_address_bits;
    u32 max_domain_address_bits;
    u32 max_domains;
    u32 max_msix_vectors;
    u32 max_reserved_ranges;
    u32 reserved;
    u64 generation;
};

struct IommuDeviceProfile {
    u32 size;
    u32 version;
    IommuBdf bdf;
    u32 isolation_group;
    u32 flags;
    u32 reset_method;
    u32 dma_address_bits;
    u32 max_msix_vectors;
    u32 rmrr_count;
    u64 profile_generation;
    IommuRange rmrr[kIommuMaxReservedRanges];
    u64 dma_mask;
    u32 reserved;
    u32 reserved2;
};

struct IommuDomain {
    u32 size;
    u32 version;
    u64 domain_id;
    u64 owner_id;
    u64 parent_domain_id;
    u64 generation;
    u32 kind;
    u32 state;
    u32 flags;
    u32 address_bits;
    u64 guest_base;
    u64 guest_limit;
    u64 mapped_pages;
    u32 reserved;
    u32 reserved2;
};

struct IommuDmaMapping {
    u32 size;
    u32 version;
    // iova is the address presented by the device. guest_physical is the
    // result of the first translation and host_physical is the final target
    u64 iova;
    u64 guest_physical;
    u64 host_physical;
    u64 page_count;
    u32 page_order;
    u32 permissions;
    u32 flags;
    u32 reserved;
    u64 generation;
};

struct IommuDmaResult {
    u32 size;
    u32 version;
    u32 status;
    u32 permissions;
    u64 host_physical;
    u64 generation;
};

struct IommuAssignment {
    u32 size;
    u32 version;
    u32 status;
    u32 state;
    IommuBdf bdf;
    u32 reset_method;
    u32 flags;
    u64 owner_id;
    u64 domain_id;
    u64 generation;
    u64 fault_count;
};

struct IommuFaultRecord {
    u32 size;
    u32 version;
    u32 reason;
    u32 access;
    IommuBdf bdf;
    u32 reserved;
    u64 address;
    u64 generation;
    u64 sequence;
};

#pragma pack(pop)

bool IsIommuBdfValid(const IommuBdf* bdf);
bool IsIommuRangeValid(const IommuRange* range, u32 address_bits);
bool IsIommuCapabilitiesValid(const IommuCapabilities* capabilities);
bool IsIommuDeviceProfileValid(const IommuDeviceProfile* profile,
                               u32 address_bits);
bool IsIommuDomainValid(const IommuDomain* domain, u32 address_bits);
bool IsIommuDmaMappingValid(const IommuDmaMapping* mapping,
                            u32 address_bits);
bool IommuDmaMappingContains(const IommuDmaMapping* mapping, u64 iova,
                             u32 address_bits);
bool IsIommuDmaAccessAllowed(u32 permissions, IommuDmaAccess access);

IommuDmaResult ResolveNestedDma(const IommuDmaMapping* l1_mapping,
                                const IommuDmaMapping* root_mapping,
                                u64 iova, IommuDmaAccess access,
                                u32 address_bits);

IommuAssignmentStatus PrepareIommuAssignment(
    const IommuCapabilities* capabilities,
    const IommuDeviceProfile* profile, const IommuDomain* domain,
    u64 owner_id, u64 generation, IommuAssignment* assignment);
bool ActivateIommuAssignment(IommuAssignment* assignment, u64 generation,
                             u32 readiness);
bool BeginIommuDetach(IommuAssignment* assignment, u64 generation,
                      u32 readiness);
bool CompleteIommuDetach(IommuAssignment* assignment, u64 generation,
                         u32 readiness);

bool IsIommuFaultRecordValid(const IommuFaultRecord* fault,
                             u32 address_bits);
bool QuarantineIommuAssignment(IommuAssignment* assignment,
                               const IommuFaultRecord* fault);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::IommuBdf) == 8,
              "IOMMU BDF ABI changed");
static_assert(sizeof(knhv::IommuRange) == 24,
              "IOMMU range ABI changed");
static_assert(sizeof(knhv::IommuCapabilities) == 48,
              "IOMMU capabilities ABI changed");
static_assert(sizeof(knhv::IommuDeviceProfile) == 160,
              "IOMMU device profile ABI changed");
static_assert(sizeof(knhv::IommuDomain) == 88,
              "IOMMU domain ABI changed");
static_assert(sizeof(knhv::IommuDmaMapping) == 64,
              "IOMMU mapping ABI changed");
static_assert(sizeof(knhv::IommuDmaResult) == 32,
              "IOMMU result ABI changed");
static_assert(sizeof(knhv::IommuAssignment) == 64,
              "IOMMU assignment ABI changed");
static_assert(sizeof(knhv::IommuFaultRecord) == 56,
              "IOMMU fault ABI changed");
#endif
