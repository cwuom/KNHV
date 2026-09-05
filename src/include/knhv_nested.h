#pragma once

#include "knhv_abi.h"

namespace knhv {

constexpr u32 kNestedModelVersion = 1U;
constexpr u32 kNestedVmcsSlots = 16U;
constexpr u32 kNestedVmcsFields = 96U;
constexpr u32 kNestedPageSize = 4096U;
constexpr u32 kNestedVmxRevisionMask = 0x7FFFFFFFU;

constexpr u64 kRflagsCarry = 1ULL;
constexpr u64 kRflagsZero = 1ULL << 6;
constexpr u32 kInstructionOperandIsRegister = 1U << 0;
constexpr u32 kDescriptorIsInline = 1U << 1;
constexpr u32 kNestedSecondaryEnableEpt = 1U << 1;
constexpr u32 kNestedSecondaryEnableVpid = 1U << 5;
constexpr u32 kNestedSecondaryEnableVmfunc = 1U << 13;

enum class VmxOpcode : u32 {
    Vmxon = 1,
    Vmxoff = 2,
    Vmclear = 3,
    Vmptrld = 4,
    Vmptrst = 5,
    Vmread = 6,
    Vmwrite = 7,
    Vmlaunch = 8,
    Vmresume = 9,
    Invept = 10,
    Invvpid = 11,
    Vmfunc = 12,
    Vmcall = 13,
};

enum class NestedAction : u32 {
    ResumeL1 = 0,
    EnterL2 = 1,
    ReflectVmexit = 2,
    InjectUndefinedInstruction = 3,
    VirtualUnsupported = 4,
    QuarantineSession = 5,
};

enum class NestedMemoryAccess : u32 {
    Read = 1,
    Write = 2,
};

using NestedTranslateFn = bool (*)(void* context, u64 linear,
                                   u64* guest_physical,
                                   u32 access);
using NestedReadFn = bool (*)(void* context, u64 guest_physical,
                              void* destination, u32 length);
using NestedWriteFn = bool (*)(void* context, u64 guest_physical,
                               const void* source, u32 length);

struct NestedMemory {
    void* context;
    NestedTranslateFn translate;
    NestedReadFn read;
    NestedWriteFn write;
};

struct NestedCapabilities {
    u32 version;
    u32 size;
    u64 feature_bits;
    u32 vmx_revision;
    u32 max_physical_address_bits;
    u32 linear_address_bits;
    u32 eptp_list_entries;
    u32 vpid_count;
    u32 pin_allowed0;
    u32 pin_allowed1;
    u32 primary_allowed0;
    u32 primary_allowed1;
    u32 secondary_allowed0;
    u32 secondary_allowed1;
    u32 exit_allowed0;
    u32 exit_allowed1;
    u32 entry_allowed0;
    u32 entry_allowed1;
    u64 cr0_fixed0;
    u64 cr0_fixed1;
    u64 cr4_fixed0;
    u64 cr4_fixed1;
};

struct VmxInstruction {
    u32 version;
    u32 size;
    VmxOpcode opcode;
    u32 instruction_length;
    u32 flags;
    u32 descriptor_type;
    u32 reserved;
    u32 encoding;
    u32 reserved2;
    // for VMXON, VMCLEAR and VMPTRLD this is the guest linear m64 operand
    u64 linear_operand;
    u64 destination;
    u64 source;
    u64 descriptor;
};

struct NestedResult {
    HvStatus status;
    NestedAction action;
    u32 instruction_error;
    u32 instruction_length;
    u32 reserved;
    u64 rflags;
    u64 value;
};

enum class Vmcs12State : u32 {
    Clear = 0,
    Active = 1,
    Launched = 2,
};

struct NestedVmcs12 {
    u64 region_gpa;
    u32 revision;
    Vmcs12State state;
    u8 allocated;
    u8 reserved[3];
    u64 fields[kNestedVmcsFields];
    u64 dirty_groups;
};

struct NestedVcpu {
    u32 version;
    u32 size;
    NestedCapabilities capabilities;
    NestedMemory memory;
    u8 vmxon_active;
    u8 l2_running;
    u8 vmxe_enabled;
    u8 reserved;
    u64 vmxon_gpa;
    u64 current_vmcs_gpa;
    u32 instruction_error;
    u32 generation;
    u32 vmcs_count;
    u32 eptp_index;
    NestedVmcs12 vmcs[kNestedVmcsSlots];
};

struct NestedExitRecord {
    u32 version;
    u32 size;
    u32 reason;
    u32 instruction_length;
    u64 qualification;
    u64 guest_linear;
    u64 guest_physical;
};

struct HvNestedInstructionIn {
    u32 version;
    u32 size;
    u64 request_id;
    HvSessionKey session;
    VmxInstruction instruction;
};

struct HvNestedInstructionOut {
    u32 version;
    u32 size;
    u64 request_id;
    HvSessionKey session;
    NestedResult result;
};

struct HvNestedExitIn {
    u32 version;
    u32 size;
    u64 request_id;
    HvSessionKey session;
    NestedExitRecord exit_record;
};

struct HvNestedExitOut {
    u32 version;
    u32 size;
    u64 request_id;
    HvSessionKey session;
    NestedResult result;
};

// the field encodings are architectural values from Intel SDM volume 3C
constexpr u32 kVmcsFieldVpid = 0x0000U;
constexpr u32 kVmcsFieldEptpIndex = 0x0004U;
constexpr u32 kVmcsFieldIoBitmapA = 0x2000U;
constexpr u32 kVmcsFieldIoBitmapB = 0x2002U;
constexpr u32 kVmcsFieldMsrBitmap = 0x2004U;
constexpr u32 kVmcsFieldEptPointer = 0x201AU;
constexpr u32 kVmcsFieldVpidAddress = 0x201CU;
constexpr u32 kVmcsFieldPinControls = 0x4000U;
constexpr u32 kVmcsFieldPrimaryControls = 0x4002U;
constexpr u32 kVmcsFieldExceptionBitmap = 0x4004U;
constexpr u32 kVmcsFieldExitControls = 0x400CU;
constexpr u32 kVmcsFieldEntryControls = 0x4012U;
constexpr u32 kVmcsFieldSecondaryControls = 0x401EU;
constexpr u32 kVmcsFieldInstructionError = 0x4400U;
constexpr u32 kVmcsFieldExitReason = 0x4402U;
constexpr u32 kVmcsFieldExitQualification = 0x6400U;
constexpr u32 kVmcsFieldGuestCr0 = 0x6800U;
constexpr u32 kVmcsFieldGuestCr3 = 0x6802U;
constexpr u32 kVmcsFieldGuestCr4 = 0x6804U;
constexpr u32 kVmcsFieldGuestRsp = 0x681CU;
constexpr u32 kVmcsFieldGuestRip = 0x681EU;
constexpr u32 kVmcsFieldGuestRflags = 0x6820U;
constexpr u32 kVmcsFieldHostCr0 = 0x6C00U;
constexpr u32 kVmcsFieldHostCr3 = 0x6C02U;
constexpr u32 kVmcsFieldHostCr4 = 0x6C04U;
constexpr u32 kVmcsFieldHostRsp = 0x6C14U;
constexpr u32 kVmcsFieldHostRip = 0x6C16U;

void InitializeNestedCapabilities(NestedCapabilities* capabilities);
void InitializeNestedVcpu(NestedVcpu* vcpu,
                          const NestedCapabilities* capabilities,
                          const NestedMemory* memory);

NestedResult DispatchNestedInstruction(NestedVcpu* vcpu,
                                        const VmxInstruction* instruction);
NestedResult ReflectNestedExit(NestedVcpu* vcpu,
                               const NestedExitRecord* exit_record);

bool ReadNestedVmcsField(const NestedVcpu* vcpu, u32 encoding, u64* value);
bool WriteNestedVmcsField(NestedVcpu* vcpu, u32 encoding, u64 value);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::VmxInstruction) == 72,
              "nested instruction ABI changed");
static_assert(sizeof(knhv::NestedResult) == 40,
              "nested result ABI changed");
static_assert(sizeof(knhv::NestedCapabilities) == 112,
              "nested capabilities ABI changed");
static_assert(sizeof(knhv::NestedExitRecord) == 40,
              "nested exit ABI changed");
static_assert(sizeof(knhv::HvNestedInstructionIn) == 104,
              "nested instruction input ABI changed");
static_assert(sizeof(knhv::HvNestedInstructionOut) == 72,
              "nested instruction output ABI changed");
static_assert(sizeof(knhv::HvNestedExitIn) == 72,
              "nested exit input ABI changed");
static_assert(sizeof(knhv::HvNestedExitOut) == 72,
              "nested exit output ABI changed");
#endif
