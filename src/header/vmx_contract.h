#pragma once

#include <stdint.h>

// ia32_vmx_procbased_ctls3 is a 64-bit allowed-one bitmap. It does not use
// the low-half mandatory-one and high-half allowed-one layout of older VMX
// capability MSRs
constexpr uint64_t HvNormalizeTertiaryControls(uint64_t requested,
                                                uint64_t allowedOne) noexcept {
    return requested & allowedOne;
}

constexpr bool HvTertiaryControlsAllowed(uint64_t requested,
                                          uint64_t allowedOne) noexcept {
    return (requested & ~allowedOne) == 0;
}
