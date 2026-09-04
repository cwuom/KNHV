#pragma once

#include <ntddk.h>

#include "common.h"

// start and stop the monitor through the driver's lifecycle owner
extern "C" NTSTATUS StartHypervisor();
extern "C" void StopHypervisor();

extern "C" bool IsHypervisorStopComplete();
extern "C" bool IsHypervisorQuarantined();
extern "C" void QuarantineHypervisorImage();
extern "C" bool RegisterSecondaryDumpCallback();
extern "C" void UnregisterSecondaryDumpCallback();

// These probes are read-only and must complete before any processor executes
// VMXON. They never modify firmware-owned VMX policy.
bool IsVmxSupported();
bool InitializeVmxFeatureContract();
bool IsCETVmcsEnabled();
bool IsXsavesEnabled();
u32 GetXsaveStateSize();
