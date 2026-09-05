#include <ntddk.h>

#include "knhv_control_device.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                 PUNICODE_STRING registry_path) {
    return knhv::KnHvInitializeControlDriver(driver_object, registry_path,
                                             FALSE);
}
