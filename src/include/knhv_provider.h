#pragma once

#include "knhv_abi.h"

namespace knhv {

// provider selection is pure and can be tested without a hypervisor
HvStatus SelectProvider(const HvProviderRequest* request,
                        const HvCapabilitySnapshot* capabilities,
                        HvProviderKind* selected);

HvCapabilitySnapshot MakeFallbackCapabilitySnapshot(bool outer_l0_active,
                                                     bool whp_available);

// v2 negotiation is pure so the same owner and capability rules can run in
// the kernel control path and in offline contract tests
HvCapabilitySnapshotV2 MakeCapabilitySnapshotV2(
    const HvCapabilitySnapshot* capabilities);
bool IsCapabilitySnapshotV2Valid(const HvCapabilitySnapshotV2* capabilities);
bool IsOwnerLeaseV2Valid(const HvOwnerLeaseV2* lease);
bool LeaseMatchesCapabilityV2(const HvOwnerLeaseV2* lease,
                              const HvCapabilitySnapshotV2* capabilities);
HvStatus SelectProviderV2(const HvProviderRequestV2* request,
                          const HvCapabilitySnapshotV2* capabilities,
                          HvProviderResponseV2* response);

}  // namespace knhv
