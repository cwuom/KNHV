#include "knhv_time.h"

#include <intrin.h>

namespace knhv {
namespace {

constexpr i64 kI64Maximum = 9223372036854775807LL;
constexpr i64 kI64Minimum = -9223372036854775807LL - 1LL;

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTimeContractVersion && size >= required &&
           size <= kTimeMaxStructSize;
}

bool AddUnsigned(u64 left, u64 right, u64* result) {
    if (result == nullptr || left > ~0ULL - right) return false;
    *result = left + right;
    return true;
}

bool AddSigned(u64 value, i64 offset, u64* result) {
    if (result == nullptr) return false;
    if (offset >= 0) {
        return AddUnsigned(value, static_cast<u64>(offset), result);
    }
    const u64 magnitude = static_cast<u64>(-(offset + 1)) + 1ULL;
    if (value < magnitude) return false;
    *result = value - magnitude;
    return true;
}

bool MultiplyShift32(u64 left, u64 right, u64* result) {
    if (result == nullptr) return false;
    u64 high = 0;
    const u64 low = _umul128(left, right, &high);
    if (high > 0xFFFFFFFFULL) return false;
    *result = (high << 32) | (low >> 32);
    return true;
}

bool DifferenceToSigned(u64 value, u64 reference, i64* result) {
    if (result == nullptr) return false;
    if (value >= reference) {
        const u64 difference = value - reference;
        if (difference > static_cast<u64>(kI64Maximum)) return false;
        *result = static_cast<i64>(difference);
        return true;
    }
    const u64 difference = reference - value;
    const u64 negative_limit = static_cast<u64>(kI64Maximum) + 1ULL;
    if (difference > negative_limit) return false;
    if (difference == negative_limit) {
        *result = kI64Minimum;
    } else {
        *result = -static_cast<i64>(difference);
    }
    return true;
}

TimeResultCode ProjectTscTransform(const TscTransform* transform,
                                   u64 source_tsc, u64* virtual_tsc) {
    if (source_tsc < transform->base_tsc) {
        return TimeResultCode::NonMonotonic;
    }
    const u64 delta = source_tsc - transform->base_tsc;
    u64 scaled = 0;
    if (!MultiplyShift32(delta, transform->scale_q32_32, &scaled)) {
        return TimeResultCode::Overflow;
    }
    u64 candidate = 0;
    if (!AddUnsigned(transform->base_virtual_tsc, scaled, &candidate) ||
        !AddSigned(candidate, transform->offset_ticks, &candidate)) {
        return TimeResultCode::Overflow;
    }
    *virtual_tsc = candidate;
    return TimeResultCode::Success;
}

}  // namespace

bool IsTscTransformValid(const TscTransform* transform) {
    return transform != nullptr &&
           IsVersionedSizeValid(transform->version, transform->size,
                                sizeof(TscTransform)) &&
           transform->scale_q32_32 != 0 && transform->generation != 0 &&
           (transform->flags & ~kTimeKnownFlagMask) == 0 &&
           transform->reserved == 0;
}

TimeResultCode ApplyTscTransform(const TscTransform* transform,
                                 u64 source_tsc, u64* virtual_tsc) {
    if (virtual_tsc == nullptr || !IsTscTransformValid(transform)) {
        return TimeResultCode::Invalid;
    }
    if ((transform->flags & kTimeFlagPaused) != 0) {
        return TimeResultCode::Paused;
    }
    u64 candidate = 0;
    const TimeResultCode status =
        ProjectTscTransform(transform, source_tsc, &candidate);
    if (status != TimeResultCode::Success) return status;
    if (transform->last_virtual_tsc != 0 &&
        candidate < transform->last_virtual_tsc) {
        if ((transform->flags & kTimeFlagMonotonicClamp) == 0) {
            return TimeResultCode::NonMonotonic;
        }
        candidate = transform->last_virtual_tsc;
    }
    *virtual_tsc = candidate;
    return TimeResultCode::Success;
}

TimeResultCode ComposeTscTransforms(const TscTransform* outer,
                                    const TscTransform* inner,
                                    u64 source_tsc, u64* virtual_tsc) {
    if (outer == nullptr || inner == nullptr ||
        outer->generation != inner->generation) {
        return TimeResultCode::GenerationMismatch;
    }
    u64 intermediate = 0;
    const TimeResultCode outer_status =
        ApplyTscTransform(outer, source_tsc, &intermediate);
    if (outer_status != TimeResultCode::Success) return outer_status;
    return ApplyTscTransform(inner, intermediate, virtual_tsc);
}

TimeResultCode ObserveTimeSample(const TscTransform* transform,
                                 u64 source_tsc, u64 reference_ticks,
                                 TimeObservation* observation) {
    if (observation == nullptr) return TimeResultCode::Invalid;
    *observation = {};
    observation->size = sizeof(*observation);
    observation->version = kTimeContractVersion;
    if (!IsTscTransformValid(transform)) {
        observation->status = static_cast<u32>(TimeResultCode::Invalid);
        return TimeResultCode::Invalid;
    }
    observation->generation = transform->generation;
    const TimeResultCode status =
        ApplyTscTransform(transform, source_tsc, &observation->virtual_tsc);
    observation->reference_ticks = reference_ticks;
    observation->status = static_cast<u32>(status);
    if (status != TimeResultCode::Success ||
        !DifferenceToSigned(observation->virtual_tsc, reference_ticks,
                            &observation->drift_ticks)) {
        if (status == TimeResultCode::Success) {
            observation->status = static_cast<u32>(TimeResultCode::Overflow);
            return TimeResultCode::Overflow;
        }
        return status;
    }
    const u64 absolute_drift = observation->drift_ticks < 0
                                   ? static_cast<u64>(-(observation->drift_ticks + 1)) +
                                         1ULL
                                   : static_cast<u64>(observation->drift_ticks);
    if (absolute_drift > transform->max_drift_ticks) {
        observation->status = static_cast<u32>(TimeResultCode::DriftExceeded);
        return TimeResultCode::DriftExceeded;
    }
    return TimeResultCode::Success;
}

bool CalibrateTscTransform(const TscQpcSample* first,
                           const TscQpcSample* second, u64 generation,
                           u64 max_drift_ticks, TscTransform* transform) {
    if (first == nullptr || second == nullptr || transform == nullptr ||
        generation == 0 || second->source_tsc <= first->source_tsc ||
        second->reference_ticks <= first->reference_ticks) {
        return false;
    }
    const u64 source_delta = second->source_tsc - first->source_tsc;
    const u64 reference_delta = second->reference_ticks - first->reference_ticks;
    const u64 high = reference_delta >> 32;
    const u64 low = reference_delta << 32;
    if (high >= source_delta) return false;
    u64 remainder = 0;
    const u64 scale = _udiv128(high, low, source_delta, &remainder);
    if (scale == 0) return false;
    *transform = {};
    transform->size = sizeof(*transform);
    transform->version = kTimeContractVersion;
    transform->base_tsc = first->source_tsc;
    transform->base_virtual_tsc = first->reference_ticks;
    transform->scale_q32_32 = scale;
    transform->generation = generation;
    transform->last_virtual_tsc = first->reference_ticks;
    transform->max_drift_ticks = max_drift_ticks;
    transform->flags = kTimeFlagMonotonicClamp;
    return true;
}

bool RebaseTscTransform(TscTransform* transform, u64 source_tsc,
                        u64 minimum_virtual_tsc) {
    if (!IsTscTransformValid(transform) ||
        (transform->flags & kTimeFlagPaused) != 0) {
        return false;
    }
    u64 projected = 0;
    const TimeResultCode status =
        ProjectTscTransform(transform, source_tsc, &projected);
    if (status != TimeResultCode::Success) return false;
    u64 target = minimum_virtual_tsc;
    if (target < transform->last_virtual_tsc) {
        target = transform->last_virtual_tsc;
    }
    if (projected < target) {
        const u64 delta = target - projected;
        if (delta > static_cast<u64>(kI64Maximum)) return false;
        const i64 adjustment = static_cast<i64>(delta);
        if (transform->offset_ticks > kI64Maximum - adjustment) {
            return false;
        }
        transform->offset_ticks += adjustment;
    }
    transform->last_virtual_tsc = target;
    return true;
}

bool NextTimeGeneration(u64 current_generation, u64* next_generation) {
    if (next_generation == nullptr || current_generation == ~0ULL) {
        return false;
    }
    *next_generation = current_generation == 0 ? 1ULL : current_generation + 1ULL;
    return true;
}

}  // namespace knhv
