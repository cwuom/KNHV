#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kCpuPolicyContractVersion = 1U;
constexpr u32 kCpuPolicyMaxStructSize = 4096U;
constexpr u32 kCpuPolicyMaxCpuidRules = 16U;
constexpr u32 kCpuPolicyMaxMsrRules = 32U;

constexpr u32 kCpuidExposeVmx = 1U << 0;
constexpr u32 kCpuidExposeHypervisor = 1U << 1;
constexpr u32 kCpuidPreserveTopology = 1U << 2;
constexpr u32 kCpuidExposeInvariantTsc = 1U << 3;
constexpr u32 kCpuidKnownPolicyMask = kCpuidExposeVmx |
                                       kCpuidExposeHypervisor |
                                       kCpuidPreserveTopology |
                                       kCpuidExposeInvariantTsc;

constexpr u32 kCpuidLeaf1EcxVmx = 1U << 5;
constexpr u32 kCpuidLeaf1EcxHypervisor = 1U << 31;
constexpr u32 kCpuidLeaf80000007EdxInvariantTsc = 1U << 8;

constexpr u32 kMsrPolicyAllowPassThrough = 1U << 0;
constexpr u32 kMsrPolicyAllowTsc = 1U << 1;
constexpr u32 kMsrPolicyAllowPat = 1U << 2;
constexpr u32 kMsrPolicyAllowDebug = 1U << 3;
constexpr u32 kMsrPolicyAllowCet = 1U << 4;
constexpr u32 kMsrPolicyKnownMask = kMsrPolicyAllowPassThrough |
                                     kMsrPolicyAllowTsc |
                                     kMsrPolicyAllowPat |
                                     kMsrPolicyAllowDebug |
                                     kMsrPolicyAllowCet;

constexpr u32 kMsrAccessRead = 0U;
constexpr u32 kMsrAccessWrite = 1U;

constexpr u32 kMsrIa32Tsc = 0x00000010U;
constexpr u32 kMsrIa32Pat = 0x00000277U;
constexpr u32 kMsrIa32Debugctl = 0x000001D9U;
constexpr u32 kMsrIa32Efer = 0xC0000080U;
constexpr u32 kMsrFsBase = 0xC0000100U;
constexpr u32 kMsrGsBase = 0xC0000101U;
constexpr u32 kMsrKernelGsBase = 0xC0000102U;
constexpr u32 kMsrIa32Xss = 0x00000DA0U;
constexpr u32 kMsrIa32UCet = 0x000006A0U;
constexpr u32 kMsrIa32SCet = 0x000006A2U;

enum class MsrAction : u32 {
    PassThrough = 0,
    Virtualized = 1,
    InjectGeneralProtection = 2,
    InjectUndefinedInstruction = 3,
};

enum class MsrDecisionStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    InjectGeneralProtection = 2,
    InjectUndefinedInstruction = 3,
};

#pragma pack(push, 8)

struct CpuidResult {
    u32 eax;
    u32 ebx;
    u32 ecx;
    u32 edx;
};

struct CpuidRule {
    u32 leaf;
    u32 subleaf;
    u32 eax_and;
    u32 ebx_and;
    u32 ecx_and;
    u32 edx_and;
    u32 reserved;
    u32 reserved2;
};

struct CpuidPolicy {
    u32 size;
    u32 version;
    u32 level;
    u32 flags;
    u32 rule_count;
    u32 reserved;
    u64 generation;
    u32 max_basic_leaf;
    u32 max_extended_leaf;
    u32 reserved2;
    u32 reserved3;
    CpuidRule rules[kCpuPolicyMaxCpuidRules];
    CpuidResult hypervisor_leaf;
};

struct MsrRule {
    u32 msr;
    u32 read_action;
    u32 write_action;
    u32 reserved;
    u64 read_mask;
    u64 write_allowed_mask;
    u64 write_required_one;
    u64 reserved2;
};

struct MsrPolicy {
    u32 size;
    u32 version;
    u32 level;
    u32 flags;
    u32 rule_count;
    u32 reserved;
    u64 generation;
    MsrRule rules[kCpuPolicyMaxMsrRules];
};

struct MsrDecision {
    u32 size;
    u32 version;
    u32 status;
    u32 action;
    u32 msr;
    u32 access;
    u32 reserved;
    u32 reserved2;
    u64 value;
    u64 generation;
};

#pragma pack(pop)

bool IsCpuidPolicyValid(const CpuidPolicy* policy);
bool FilterCpuid(const CpuidPolicy* policy, u32 leaf, u32 subleaf,
                 const CpuidResult* host, CpuidResult* guest);

bool IsMsrPolicyValid(const MsrPolicy* policy);
bool EvaluateMsrAccess(const MsrPolicy* policy, u32 msr, bool write,
                       u64 value, MsrDecision* decision);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::CpuidResult) == 16,
              "CPUID result ABI changed");
static_assert(sizeof(knhv::CpuidRule) == 32,
              "CPUID rule ABI changed");
static_assert(sizeof(knhv::CpuidPolicy) == 576,
              "CPUID policy ABI changed");
static_assert(sizeof(knhv::MsrRule) == 48,
              "MSR rule ABI changed");
static_assert(sizeof(knhv::MsrPolicy) == 1568,
              "MSR policy ABI changed");
static_assert(sizeof(knhv::MsrDecision) == 48,
              "MSR decision ABI changed");
#endif
