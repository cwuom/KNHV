#pragma once

#include <ntddk.h>

#include "knhv_control_ioctl.h"

namespace knhv {

constexpr u32 kMaxClientSessions = 4U;
constexpr u32 kNestedGuestMemoryBytes = 64U * 1024U;

struct KnHvClientSession {
    u8 active;
    u8 nested_ready;
    u16 reserved;
    PFILE_OBJECT owner_file;
    HvSessionStatusOut status;
    HvOwnerLeaseV2 lease;
    u8 lease_active;
    u8 lease_reserved[7];
    NestedVcpu nested_vcpu;
    u8 guest_memory[kNestedGuestMemoryBytes];
};

struct KnHvDeviceExtension {
    PDEVICE_OBJECT device;
    UNICODE_STRING dos_name;
    KSPIN_LOCK state_lock;
    IO_REMOVE_LOCK remove_lock;
    u8 nested_test_driver;
    u8 initialized;
    u16 reserved;
    u64 next_client;
    u32 active_sessions;
    u32 reserved2;
    HvCapabilitySnapshot capabilities;
    KnHvClientSession sessions[kMaxClientSessions];
};

extern "C" NTSTATUS KnHvInitializeControlDriver(
    PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path,
    BOOLEAN nested_test_driver);
extern "C" void KnHvUnloadControlDriver(PDRIVER_OBJECT driver_object);
extern "C" NTSTATUS KnHvDispatchCreate(PDEVICE_OBJECT device_object,
                                        PIRP irp);
extern "C" NTSTATUS KnHvDispatchClose(PDEVICE_OBJECT device_object,
                                       PIRP irp);
extern "C" NTSTATUS KnHvDispatchUnsupported(PDEVICE_OBJECT device_object,
                                              PIRP irp);
extern "C" NTSTATUS KnHvDispatchDeviceControl(PDEVICE_OBJECT device_object,
                                               PIRP irp);

}  // namespace knhv
