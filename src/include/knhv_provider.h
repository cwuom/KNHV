#pragma once

#include "knhv_abi.h"

namespace knhv {

// provider selection is pure and can be tested without a hypervisor
HvStatus SelectProvider(const HvProviderRequest* request,
                        const HvCapabilitySnapshot* capabilities,
                        HvProviderKind* selected);

HvCapabilitySnapshot MakeFallbackCapabilitySnapshot(bool outer_l0_active,
                                                     bool whp_available);

}  // namespace knhv
