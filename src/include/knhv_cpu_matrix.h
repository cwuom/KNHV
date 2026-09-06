#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kCpuMatrixContractVersion = 1U;
constexpr u32 kCpuMatrixMaxStructSize = 4096U;
constexpr u32 kCpuMatrixMaxProcessors = 4096U;

constexpr u64 kCpuMatrixFeatureVmx = 1ULL << 0;
constexpr u64 kCpuMatrixFeatureHypervisor = 1ULL << 1;
constexpr u64 kCpuMatrixFeatureInvariantTsc = 1ULL << 2;
constexpr u64 kCpuMatrixFeatureXsave = 1ULL << 3;
constexpr u64 kCpuMatrixFeaturePcide = 1ULL << 4;
constexpr u64 kCpuMatrixFeatureInvpcid = 1ULL << 5;
constexpr u64 kCpuMatrixFeatureFsgsbase = 1ULL << 6;
constexpr u64 kCpuMatrixFeatureSmep = 1ULL << 7;
constexpr u64 kCpuMatrixFeatureSmap = 1ULL << 8;
constexpr u64 kCpuMatrixFeatureTscDeadline = 1ULL << 9;
constexpr u64 kCpuMatrixFeatureCetIbt = 1ULL << 10;
constexpr u64 kCpuMatrixKnownFeatureMask = (1ULL << 11) - 1ULL;

constexpr u32 kCpuMatrixSampleCollected = 1U << 0;
constexpr u32 kCpuMatrixSampleAffinityFailed = 1U << 1;
constexpr u32 kCpuMatrixSampleMigrated = 1U << 2;
constexpr u32 kCpuMatrixSampleCpuidFailed = 1U << 3;
constexpr u32 kCpuMatrixKnownSampleStatusMask =
    kCpuMatrixSampleCollected | kCpuMatrixSampleAffinityFailed |
    kCpuMatrixSampleMigrated | kCpuMatrixSampleCpuidFailed;

constexpr u32 kCpuMatrixSummaryAllVmx = 1U << 0;
constexpr u32 kCpuMatrixSummaryAllInvariantTsc = 1U << 1;
constexpr u32 kCpuMatrixSummaryAnyHypervisor = 1U << 2;
constexpr u32 kCpuMatrixSummaryIdentityUniform = 1U << 3;
constexpr u32 kCpuMatrixSummarySamplesComplete = 1U << 4;
constexpr u32 kCpuMatrixSummaryHasInvalidSamples = 1U << 5;
constexpr u32 kCpuMatrixKnownSummaryFlagMask =
    kCpuMatrixSummaryAllVmx | kCpuMatrixSummaryAllInvariantTsc |
    kCpuMatrixSummaryAnyHypervisor | kCpuMatrixSummaryIdentityUniform |
    kCpuMatrixSummarySamplesComplete | kCpuMatrixSummaryHasInvalidSamples;

enum class CpuMatrixState : u32 {
    Empty = 0,
    CompleteUniform = 1,
    CompleteMixed = 2,
    Incomplete = 3,
    Invalid = 4,
};

#pragma pack(push, 8)

struct CpuMatrixSample {
    u32 size;
    u32 version;
    u32 logical_index;
    u32 processor_group;
    u32 processor_number;
    u32 status;
    u64 feature_flags;
    u32 max_basic_leaf;
    u32 max_extended_leaf;
    u32 leaf7_max_subleaf;
    u32 physical_address_bits;
    u32 linear_address_bits;
    u32 vendor_ebx;
    u32 vendor_ecx;
    u32 vendor_edx;
    u32 hypervisor_ebx;
    u32 hypervisor_ecx;
    u32 hypervisor_edx;
    u32 leaf1_ecx;
    u32 leaf1_edx;
    u32 leaf7_ebx;
    u32 leaf7_ecx;
    u32 leaf7_edx;
    u32 extended_leaf7_edx;
    u32 extended_leaf8_eax;
    u32 reserved[2];
};

struct CpuMatrixSummary {
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
    u32 common_max_basic_leaf;
    u32 common_max_extended_leaf;
    u32 common_physical_address_bits;
    u32 common_linear_address_bits;
    u32 vendor_ebx;
    u32 vendor_ecx;
    u32 vendor_edx;
    u32 reserved[3];
};

#pragma pack(pop)

bool IsCpuMatrixSampleValid(const CpuMatrixSample* sample);
bool IsCpuMatrixSampleUsable(const CpuMatrixSample* sample);
bool BuildCpuMatrixSummary(const CpuMatrixSample* samples, u32 sample_count,
                           u32 expected_count, CpuMatrixSummary* summary);
bool IsCpuMatrixSummaryValid(const CpuMatrixSummary* summary);
bool IsCpuMatrixUniform(const CpuMatrixSummary* summary,
                        u64 required_features);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::CpuMatrixSample) == 112,
              "CPU matrix sample ABI changed");
static_assert(sizeof(knhv::CpuMatrixSummary) == 96,
              "CPU matrix summary ABI changed");
#endif
