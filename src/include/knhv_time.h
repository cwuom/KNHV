#pragma once

#include "knhv_abi.h"

namespace knhv {

using i64 = signed __int64;

constexpr u32 kTimeContractVersion = 1U;
constexpr u32 kTimeMaxStructSize = 4096U;
constexpr u64 kTimeScaleOneQ32_32 = 1ULL << 32;
constexpr u32 kTimeFlagInvariantTsc = 1U << 0;
constexpr u32 kTimeFlagMonotonicClamp = 1U << 1;
constexpr u32 kTimeFlagPaused = 1U << 2;
constexpr u32 kTimeKnownFlagMask = kTimeFlagInvariantTsc |
                                    kTimeFlagMonotonicClamp |
                                    kTimeFlagPaused;

enum class TimeResultCode : u32 {
    Success = 0,
    Invalid = 1,
    Overflow = 2,
    NonMonotonic = 3,
    DriftExceeded = 4,
    GenerationMismatch = 5,
    Paused = 6,
};

#pragma pack(push, 8)

struct TscTransform {
    u32 size;
    u32 version;
    u64 base_tsc;
    u64 base_virtual_tsc;
    u64 scale_q32_32;
    i64 offset_ticks;
    u64 generation;
    u64 last_virtual_tsc;
    u64 max_drift_ticks;
    u32 flags;
    u32 reserved;
};

struct TscQpcSample {
    u64 source_tsc;
    u64 reference_ticks;
};

struct TimeObservation {
    u32 size;
    u32 version;
    u64 virtual_tsc;
    u64 reference_ticks;
    i64 drift_ticks;
    u64 generation;
    u32 status;
    u32 reserved;
};

#pragma pack(pop)

bool IsTscTransformValid(const TscTransform* transform);
TimeResultCode ApplyTscTransform(const TscTransform* transform,
                                 u64 source_tsc, u64* virtual_tsc);
TimeResultCode ComposeTscTransforms(const TscTransform* outer,
                                    const TscTransform* inner,
                                    u64 source_tsc, u64* virtual_tsc);
TimeResultCode ObserveTimeSample(const TscTransform* transform,
                                 u64 source_tsc, u64 reference_ticks,
                                 TimeObservation* observation);
bool CalibrateTscTransform(const TscQpcSample* first,
                           const TscQpcSample* second, u64 generation,
                           u64 max_drift_ticks, TscTransform* transform);
bool RebaseTscTransform(TscTransform* transform, u64 source_tsc,
                        u64 minimum_virtual_tsc);
bool NextTimeGeneration(u64 current_generation, u64* next_generation);

}  // namespace knhv

#ifdef __cplusplus
static_assert(sizeof(knhv::TscTransform) == 72,
              "TSC transform ABI changed");
static_assert(sizeof(knhv::TscQpcSample) == 16,
              "TSC sample ABI changed");
static_assert(sizeof(knhv::TimeObservation) == 48,
              "time observation ABI changed");
#endif
