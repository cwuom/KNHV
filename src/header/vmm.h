//
// Created by cwuom on 17 Feb 2026.
//

#pragma once
#include <ntddk.h>

/*
 * vmm.h
 * defines the public interface for the hypervisor
 * included by main.cpp to call Start/Stop functions
 */

// start the hypervisor on all logical processors
extern "C" NTSTATUS StartHypervisor();

// stop the hypervisor and release all allocated resources
extern "C" void StopHypervisor();

// Hardware/firmware gate implemented in main.cpp.  The gate is deliberately
// read-only: it never changes IA32_FEATURE_CONTROL or otherwise claims VMX
// ownership when firmware/another hypervisor has already configured it.
bool IsVmxSupported();
