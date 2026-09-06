#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kWhpContractVersion = 1U;
constexpr u32 kWhpMaxStructSize = 4096U;
constexpr u32 kWhpPageSize = 4096U;
constexpr u32 kWhpMaxPhysicalAddressBits = 52U;
constexpr u32 kWhpMaxVcpus = 256U;
constexpr u32 kWhpMaxMappings = 1024U;

constexpr u64 kWhpCapPartition = 1ULL << 0;
constexpr u64 kWhpCapLocalApic = 1ULL << 1;
constexpr u64 kWhpCapXsave = 1ULL << 2;
constexpr u64 kWhpCapDirtyPageTracking = 1ULL << 3;
constexpr u64 kWhpCapVirtualPci = 1ULL << 4;
constexpr u64 kWhpCapIommu = 1ULL << 5;
constexpr u64 kWhpCapNestedVmx = 1ULL << 6;
constexpr u64 kWhpCapReferenceTime = 1ULL << 7;
constexpr u64 kWhpCapExtendedExits = 1ULL << 8;
constexpr u64 kWhpKnownCapabilityMask =
    kWhpCapPartition | kWhpCapLocalApic | kWhpCapXsave |
    kWhpCapDirtyPageTracking | kWhpCapVirtualPci | kWhpCapIommu |
    kWhpCapNestedVmx | kWhpCapReferenceTime | kWhpCapExtendedExits;

constexpr u64 kWhpExitCpuid = 1ULL << 0;
constexpr u64 kWhpExitMsr = 1ULL << 1;
constexpr u64 kWhpExitException = 1ULL << 2;
constexpr u64 kWhpExitRdtsc = 1ULL << 3;
constexpr u64 kWhpExitApicSmi = 1ULL << 4;
constexpr u64 kWhpExitHypercall = 1ULL << 5;
constexpr u64 kWhpExitApicInitSipi = 1ULL << 6;
constexpr u64 kWhpExitApicWriteLint0 = 1ULL << 7;
constexpr u64 kWhpExitApicWriteLint1 = 1ULL << 8;
constexpr u64 kWhpExitApicWriteSvr = 1ULL << 9;
constexpr u64 kWhpExitUnknownSynic = 1ULL << 10;
constexpr u64 kWhpExitRetargetVpci = 1ULL << 11;
constexpr u64 kWhpExitApicWriteLdr = 1ULL << 12;
constexpr u64 kWhpExitApicWriteDfr = 1ULL << 13;
constexpr u64 kWhpExitGpaFault = 1ULL << 14;
constexpr u64 kWhpKnownExtendedExitMask =
    (1ULL << 15) - 1ULL;

constexpr u32 kWhpPartitionEnableNestedVmx = 1U << 0;
constexpr u32 kWhpPartitionEnableLocalApic = 1U << 1;
constexpr u32 kWhpPartitionEnableReferenceTime = 1U << 2;
constexpr u32 kWhpPartitionRequireIsolation = 1U << 3;
constexpr u32 kWhpKnownPartitionFlagMask =
    kWhpPartitionEnableNestedVmx | kWhpPartitionEnableLocalApic |
    kWhpPartitionEnableReferenceTime | kWhpPartitionRequireIsolation;

constexpr u32 kWhpMappingRead = 1U << 0;
constexpr u32 kWhpMappingWrite = 1U << 1;
constexpr u32 kWhpMappingExecute = 1U << 2;
constexpr u32 kWhpKnownMappingPermissionMask =
    kWhpMappingRead | kWhpMappingWrite | kWhpMappingExecute;
constexpr u32 kWhpMappingPrivate = 1U << 0;
constexpr u32 kWhpMappingDirtyTrack = 1U << 1;
constexpr u32 kWhpKnownMappingFlagMask = kWhpMappingPrivate |
                                          kWhpMappingDirtyTrack;

enum class WhpStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    CapabilityMismatch = 2,
    StateConflict = 3,
    GenerationMismatch = 4,
    AddressInvalid = 5,
    LimitExceeded = 6,
    ExitUnsupported = 7,
    Quarantined = 8,
};

enum class WhpPartitionState : u32 {
    Empty = 0,
    Created = 1,
    Configured = 2,
    Running = 3,
    Draining = 4,
    Closed = 5,
    Quarantined = 6,
};

enum class WhpVcpuState : u32 {
    Empty = 0,
    Created = 1,
    Running = 2,
    Stopped = 3,
    Failed = 4,
};

enum class WhpExitReason : u32 {
    None = 0x00000000,
    MemoryAccess = 0x00000001,
    IoPortAccess = 0x00000002,
    UnrecoverableException = 0x00000004,
    InvalidVpRegisterValue = 0x00000005,
    UnsupportedFeature = 0x00000006,
    InterruptWindow = 0x00000007,
    Halt = 0x00000008,
    ApicEoi = 0x00000009,
    MsrAccess = 0x00001000,
    Cpuid = 0x00001001,
    Exception = 0x00001002,
    Rdtsc = 0x00001003,
    Hypercall = 0x00001005,
    Canceled = 0x00002001,
};

enum class WhpExitAction : u32 {
    Resume = 0,
    HandleMemory = 1,
    HandleIo = 2,
    HandleCpu = 3,
    InjectException = 4,
    Stop = 5,
    Quarantine = 6,
};

#pragma pack(push, 8)

struct WhpCapabilities {
    u32 size;
    u32 version;
    u64 feature_flags;
    u64 extended_exit_flags;
    u32 api_version;
    u32 physical_address_bits;
    u32 max_vcpus;
    u32 reserved;
    u64 processor_clock_hz;
    u64 generation;
};

struct WhpPartitionConfig {
    u32 size;
    u32 version;
    u64 owner_id;
    u64 generation;
    u32 max_vcpus;
    u32 physical_address_bits;
    u32 flags;
    u32 reserved;
};

struct WhpPartition {
    u32 size;
    u32 version;
    u64 partition_id;
    u64 owner_id;
    u64 generation;
    u32 state;
    u32 flags;
    u32 max_vcpus;
    u32 configured_vcpus;
    u32 mapping_count;
    u32 reserved;
    u64 mapped_pages;
};

struct WhpMemoryMapping {
    u32 size;
    u32 version;
    u64 guest_physical;
    u64 host_address;
    u64 page_count;
    u32 permissions;
    u32 flags;
    u64 generation;
};

struct WhpVcpu {
    u32 size;
    u32 version;
    u32 index;
    u32 state;
    u64 generation;
    u64 run_count;
    u64 exit_count;
};

struct WhpExitRecord {
    u32 size;
    u32 version;
    u32 reason;
    u32 vcpu_index;
    u32 instruction_length;
    u32 reserved;
    u64 qualification;
    u64 guest_physical;
    u64 guest_linear;
    u64 generation;
};

struct WhpExitDecision {
    u32 size;
    u32 version;
    u32 status;
    u32 action;
    u32 reason;
    u32 reserved;
    u64 generation;
};

#pragma pack(pop)

bool IsWhpCapabilitiesValid(const WhpCapabilities* capabilities);
bool IsWhpPartitionConfigValid(const WhpPartitionConfig* config);
bool IsWhpPartitionValid(const WhpPartition* partition);
bool IsWhpMemoryMappingValid(const WhpMemoryMapping* mapping,
                             u32 physical_address_bits);
bool IsWhpVcpuValid(const WhpVcpu* vcpu);
bool IsWhpExitRecordValid(const WhpExitRecord* record);

WhpStatus CreateWhpPartition(const WhpCapabilities* capabilities,
                             const WhpPartitionConfig* config,
                             u64 partition_id, WhpPartition* partition);
WhpStatus ConfigureWhpPartition(WhpPartition* partition, u64 generation,
                                u32 vcpu_count);
WhpStatus MapWhpGpa(WhpPartition* partition,
                    const WhpMemoryMapping* mapping, u64 generation,
                    u32 physical_address_bits);
WhpStatus CreateWhpVcpu(const WhpPartition* partition, WhpVcpu* vcpu,
                        u32 index, u64 generation);
WhpStatus StartWhpVcpu(WhpPartition* partition, WhpVcpu* vcpu,
                       u64 generation);
WhpStatus StopWhpVcpu(WhpPartition* partition, WhpVcpu* vcpu,
                      u64 generation);
bool StartWhpPartition(WhpPartition* partition, u64 generation);
bool BeginWhpDrain(WhpPartition* partition, u64 generation);
bool CloseWhpPartition(WhpPartition* partition, u64 generation);
bool QuarantineWhpPartition(WhpPartition* partition, u64 generation);
bool EvaluateWhpExit(const WhpPartition* partition,
                     const WhpExitRecord* record, u64 generation,
                     WhpExitDecision* decision);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::WhpCapabilities) == 56,
              "WHP capabilities ABI changed");
static_assert(sizeof(knhv::WhpPartitionConfig) == 40,
              "WHP partition config ABI changed");
static_assert(sizeof(knhv::WhpPartition) == 64,
              "WHP partition ABI changed");
static_assert(sizeof(knhv::WhpMemoryMapping) == 48,
              "WHP mapping ABI changed");
static_assert(sizeof(knhv::WhpVcpu) == 40,
              "WHP vCPU ABI changed");
static_assert(sizeof(knhv::WhpExitRecord) == 56,
              "WHP exit ABI changed");
static_assert(sizeof(knhv::WhpExitDecision) == 32,
              "WHP decision ABI changed");
#endif
