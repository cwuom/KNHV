#pragma once

#include "knhv_nested.h"

namespace knhv {
namespace nested_internal {

struct FieldRule {
    u32 encoding;
    u8 width;
    u8 writable;
    u8 control_kind;
    u8 clean_group;
    u64 reserved_zero_mask;
    u64 reserved_one_mask;
};

enum FieldControlKind : u8 {
    FieldControlNone = 0,
    FieldControlPin = 1,
    FieldControlPrimary = 2,
    FieldControlSecondary = 3,
    FieldControlExit = 4,
    FieldControlEntry = 5,
};

const FieldRule* FindFieldRule(u32 encoding);
u32 FieldIndex(const FieldRule* rule);
bool IsCanonicalAddress(u64 value, u32 address_bits);
bool IsLinearRangeCanonical(const NestedVcpu* vcpu, u64 linear, u32 length);
bool IsPhysicalAddress(u64 value, u32 address_bits);
bool IsAlignedPage(u64 value);
bool ReadLinear(const NestedMemory& memory, u64 linear, void* buffer,
                u32 length, u32 access);
bool WriteLinear(const NestedMemory& memory, u64 linear, const void* buffer,
                 u32 length);
bool TranslateLinear(const NestedMemory& memory, u64 linear, u32 access,
                     u64* guest_physical);

NestedResult MakeResult(HvStatus status, NestedAction action,
                        u32 instruction_error, u32 instruction_length,
                        u64 rflags, u64 value);
NestedResult MakeSuccess(NestedAction action, u32 instruction_length,
                         u64 value = 0);
NestedResult MakeVmfail(NestedVcpu* vcpu, HvStatus status,
                        u32 instruction_error, u32 instruction_length);
void ClearVmInstructionError(NestedVcpu* vcpu);

NestedVmcs12* FindVmcs(NestedVcpu* vcpu, u64 region_gpa);
const NestedVmcs12* FindVmcs(const NestedVcpu* vcpu, u64 region_gpa);
NestedVmcs12* CurrentVmcs(NestedVcpu* vcpu);
const NestedVmcs12* CurrentVmcs(const NestedVcpu* vcpu);

bool ValidateVmxRegion(NestedVcpu* vcpu, u64 operand_linear,
                       u64* region_gpa);
bool ValidateControlValue(const NestedVcpu* vcpu, const FieldRule& rule,
                          u64 value);
bool ValidateEntryState(const NestedVcpu* vcpu, const NestedVmcs12& vmcs);
void SetVmcsReadOnly(NestedVmcs12* vmcs, u32 encoding, u64 value);

}  // namespace nested_internal
}  // namespace knhv
