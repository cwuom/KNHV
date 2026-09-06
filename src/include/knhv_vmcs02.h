#pragma once

#include "knhv_ept.h"
#include "knhv_nested.h"

namespace knhv {

constexpr u32 kVmcs02ModelVersion = 1U;
constexpr u32 kVmcs02MaxStructSize = 4096U;
constexpr u32 kVmcs02PrimaryActivateSecondary = 1U << 31;

enum class Vmcs02BuildStatus : u32 {
    Success = 0,
    InvalidParameter = 1,
    Vmcs12Invalid = 2,
    ControlConflict = 3,
    CapabilityMismatch = 4,
    AddressInvalid = 5,
    GenerationMismatch = 6,
};

#pragma pack(push, 8)

struct Vmcs12Model {
    u32 size;
    u32 version;
    u32 revision;
    u32 state;
    u32 pin_controls;
    u32 primary_controls;
    u32 secondary_controls;
    u32 exit_controls;
    u32 entry_controls;
    u32 exception_bitmap;
    u32 reserved;
    u64 guest_cr0;
    u64 guest_cr3;
    u64 guest_cr4;
    u64 guest_rip;
    u64 guest_rsp;
    u64 guest_rflags;
    u64 ept_pointer;
    u64 vpid;
};

struct Vmcs02Policy {
    u32 size;
    u32 version;
    u32 required_pin_controls;
    u32 required_primary_controls;
    u32 required_secondary_controls;
    u32 required_exit_controls;
    u32 required_entry_controls;
    u32 forbidden_pin_controls;
    u32 forbidden_primary_controls;
    u32 forbidden_secondary_controls;
    u32 forbidden_exit_controls;
    u32 forbidden_entry_controls;
    u32 reserved;
    u64 host_cr0;
    u64 host_cr3;
    u64 host_cr4;
    u64 host_rsp;
    u64 host_rip;
    u64 ept_pointer;
    u64 io_bitmap_a;
    u64 io_bitmap_b;
    u64 msr_bitmap;
    u64 generation;
};

struct Vmcs02Image {
    u32 size;
    u32 version;
    u32 status;
    u32 reserved;
    u32 pin_controls;
    u32 primary_controls;
    u32 secondary_controls;
    u32 exit_controls;
    u32 entry_controls;
    u32 exception_bitmap;
    u32 reserved2;
    u64 guest_cr0;
    u64 guest_cr3;
    u64 guest_cr4;
    u64 guest_rip;
    u64 guest_rsp;
    u64 guest_rflags;
    u64 host_cr0;
    u64 host_cr3;
    u64 host_cr4;
    u64 host_rsp;
    u64 host_rip;
    u64 ept_pointer;
    u64 io_bitmap_a;
    u64 io_bitmap_b;
    u64 msr_bitmap;
    u64 generation;
};

#pragma pack(pop)

bool ReadVmcs12Model(const NestedVcpu* vcpu, const NestedVmcs12* vmcs,
                     Vmcs12Model* model);
bool IsVmcs12ModelValid(const Vmcs12Model* model,
                        const NestedCapabilities* capabilities);
Vmcs02BuildStatus BuildVmcs02Model(const Vmcs12Model* vmcs12,
                                    const NestedCapabilities* capabilities,
                                    const Vmcs02Policy* policy,
                                    Vmcs02Image* image);
bool IsVmcs02ImageValid(const Vmcs02Image* image,
                        const NestedCapabilities* capabilities,
                        const Vmcs02Policy* policy);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::Vmcs12Model) == 112,
              "VMCS12 model ABI changed");
static_assert(sizeof(knhv::Vmcs02Policy) == 136,
              "VMCS02 policy ABI changed");
static_assert(sizeof(knhv::Vmcs02Image) == 176,
              "VMCS02 image ABI changed");
#endif
