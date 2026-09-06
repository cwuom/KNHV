#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kExitContractVersion = 1U;
constexpr u32 kExitMaxStructSize = 4096U;
constexpr u32 kExitMaxInstructionLength = 15U;

constexpr u32 kExitPolicyVirtualizeCpuid = 1U << 0;
constexpr u32 kExitPolicyVirtualizeTsc = 1U << 1;
constexpr u32 kExitPolicyVirtualizeMsr = 1U << 2;
constexpr u32 kExitPolicyReflectVmx = 1U << 3;
constexpr u32 kExitPolicyReflectEpt = 1U << 4;
constexpr u32 kExitPolicyAllowIo = 1U << 5;
constexpr u32 kExitKnownPolicyMask =
    kExitPolicyVirtualizeCpuid | kExitPolicyVirtualizeTsc |
    kExitPolicyVirtualizeMsr | kExitPolicyReflectVmx |
    kExitPolicyReflectEpt | kExitPolicyAllowIo;

constexpr u32 kExitRecordHostOwned = 1U << 0;
constexpr u32 kExitRecordEntryFailure = 1U << 1;
constexpr u32 kExitKnownRecordMask =
    kExitRecordHostOwned | kExitRecordEntryFailure;

enum class ExitReason : u32 {
    ExceptionOrNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InterruptWindow = 7,
    NmiWindow = 8,
    Cpuid = 10,
    Hlt = 12,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmxoff = 26,
    Vmxon = 27,
    CrAccess = 28,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    InvalidGuestState = 33,
    MsrLoading = 34,
    Mwait = 36,
    MonitorTrap = 37,
    Monitor = 39,
    Pause = 40,
    MachineCheck = 41,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    Invvpid = 53,
    Xsetbv = 55,
    ApicWrite = 56,
    Invpcid = 58,
    Vmfunc = 59,
    Xsaves = 63,
    Xrstors = 64,
};

enum class ExitClass : u32 {
    Unknown = 0,
    Interrupt = 1,
    NestedVmx = 2,
    CpuControl = 3,
    Time = 4,
    Msr = 5,
    Io = 6,
    Memory = 7,
    GuestState = 8,
    Fatal = 9,
};

constexpr u32 kExitClassInterrupt = 1U << 0;
constexpr u32 kExitClassNestedVmx = 1U << 1;
constexpr u32 kExitClassCpuControl = 1U << 2;
constexpr u32 kExitClassTime = 1U << 3;
constexpr u32 kExitClassMsr = 1U << 4;
constexpr u32 kExitClassIo = 1U << 5;
constexpr u32 kExitClassMemory = 1U << 6;
constexpr u32 kExitClassGuestState = 1U << 7;
constexpr u32 kExitClassFatal = 1U << 8;
constexpr u32 kExitKnownClassMask =
    kExitClassInterrupt | kExitClassNestedVmx | kExitClassCpuControl |
    kExitClassTime | kExitClassMsr | kExitClassIo | kExitClassMemory |
    kExitClassGuestState | kExitClassFatal;

enum class ExitAction : u32 {
    ResumeGuest = 0,
    ReflectToL1 = 1,
    InjectUndefinedInstruction = 2,
    InjectGeneralProtection = 3,
    QuarantineVcpu = 4,
    FatalHost = 5,
};

enum class ExitDecisionStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    GenerationMismatch = 2,
    UnsupportedReason = 3,
    QuarantineRequired = 4,
};

#pragma pack(push, 8)

struct ExitPolicy {
    u32 size;
    u32 version;
    u32 level;
    u32 flags;
    u32 allowed_classes;
    u32 max_instruction_length;
    u64 generation;
    u64 reserved;
};

struct ExitRecord {
    u32 size;
    u32 version;
    u32 reason;
    u32 instruction_length;
    u32 flags;
    u32 reserved;
    u64 qualification;
    u64 guest_linear;
    u64 guest_physical;
    u64 guest_rip;
    u64 generation;
};

struct ExitDecision {
    u32 size;
    u32 version;
    u32 status;
    u32 action;
    u32 reason;
    u32 exception_vector;
    u32 instruction_length;
    u32 reserved;
    u64 generation;
};

#pragma pack(pop)

ExitClass ClassifyExitReason(u32 reason);
bool IsExitPolicyValid(const ExitPolicy* policy, u32 linear_address_bits);
bool IsExitRecordValid(const ExitRecord* record, u32 physical_address_bits,
                       u32 linear_address_bits);
bool EvaluateExit(const ExitRecord* record, const ExitPolicy* policy,
                  u32 physical_address_bits, u32 linear_address_bits,
                  ExitDecision* decision);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::ExitPolicy) == 40,
              "exit policy ABI changed");
static_assert(sizeof(knhv::ExitRecord) == 64,
              "exit record ABI changed");
static_assert(sizeof(knhv::ExitDecision) == 40,
              "exit decision ABI changed");
#endif
