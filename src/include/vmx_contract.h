#pragma once

#include <stdint.h>

// IA32_VMX_PROCBASED_CTLS3 is an allowed-one bitmap, unlike the two-half
// layout used by the older VMX capability MSRs
constexpr uint64_t HvNormalizeTertiaryControls(uint64_t requested,
                                                uint64_t allowedOne) noexcept {
    return requested & allowedOne;
}

constexpr bool HvTertiaryControlsAllowed(uint64_t requested,
                                          uint64_t allowedOne) noexcept {
    return (requested & ~allowedOne) == 0;
}
