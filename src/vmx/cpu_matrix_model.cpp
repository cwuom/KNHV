#include "knhv_cpu_matrix.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kCpuMatrixContractVersion && size >= required &&
           size <= kCpuMatrixMaxStructSize;
}

bool IsStateValid(u32 state) {
    return state <= static_cast<u32>(CpuMatrixState::Invalid);
}

bool IsCollected(const CpuMatrixSample& sample) {
    return (sample.status & kCpuMatrixSampleCollected) != 0 &&
           (sample.status & (kCpuMatrixSampleAffinityFailed |
                             kCpuMatrixSampleMigrated |
                             kCpuMatrixSampleCpuidFailed)) == 0;
}

bool SameIdentity(const CpuMatrixSample& left,
                  const CpuMatrixSample& right) {
    return left.vendor_ebx == right.vendor_ebx &&
           left.vendor_ecx == right.vendor_ecx &&
           left.vendor_edx == right.vendor_edx &&
           left.hypervisor_ebx == right.hypervisor_ebx &&
           left.hypervisor_ecx == right.hypervisor_ecx &&
           left.hypervisor_edx == right.hypervisor_edx &&
           left.max_basic_leaf == right.max_basic_leaf &&
           left.max_extended_leaf == right.max_extended_leaf &&
           left.physical_address_bits == right.physical_address_bits &&
           left.linear_address_bits == right.linear_address_bits;
}

void InitializeSummary(CpuMatrixSummary* summary, u32 expected_count,
                       u32 sample_count) {
    *summary = {};
    summary->size = sizeof(*summary);
    summary->version = kCpuMatrixContractVersion;
    summary->state = static_cast<u32>(CpuMatrixState::Invalid);
    summary->expected_count = expected_count;
    summary->sample_count = sample_count;
}

}  // namespace

bool IsCpuMatrixSampleValid(const CpuMatrixSample* sample) {
    if (sample == nullptr ||
        !IsVersionedSizeValid(sample->version, sample->size,
                              sizeof(CpuMatrixSample)) ||
        sample->logical_index >= kCpuMatrixMaxProcessors ||
        sample->processor_number >= sizeof(u64) * 8U ||
        (sample->status & ~kCpuMatrixKnownSampleStatusMask) != 0 ||
        (sample->feature_flags & ~kCpuMatrixKnownFeatureMask) != 0 ||
        sample->max_basic_leaf >= 0x80000000U ||
        sample->physical_address_bits > 52U ||
        sample->linear_address_bits > 64U || sample->reserved[0] != 0 ||
        sample->reserved[1] != 0) {
        return false;
    }
    if (IsCollected(*sample)) {
        if (sample->max_basic_leaf < 1U ||
            sample->max_extended_leaf < 0x80000000U ||
            sample->vendor_ebx == 0U && sample->vendor_ecx == 0U &&
                sample->vendor_edx == 0U) {
            return false;
        }
    }
    return true;
}

bool IsCpuMatrixSampleUsable(const CpuMatrixSample* sample) {
    return IsCpuMatrixSampleValid(sample) && sample != nullptr &&
           IsCollected(*sample);
}

bool BuildCpuMatrixSummary(const CpuMatrixSample* samples, u32 sample_count,
                           u32 expected_count, CpuMatrixSummary* summary) {
    if (summary == nullptr || sample_count > kCpuMatrixMaxProcessors ||
        (sample_count != 0U && samples == nullptr)) {
        if (summary != nullptr) InitializeSummary(summary, expected_count,
                                                  sample_count);
        return false;
    }

    InitializeSummary(summary, expected_count, sample_count);
    if (sample_count == 0U) {
        summary->state = expected_count == 0U
                             ? static_cast<u32>(CpuMatrixState::Empty)
                             : static_cast<u32>(CpuMatrixState::Incomplete);
        if (expected_count == 0U) {
            summary->flags |= kCpuMatrixSummarySamplesComplete;
        }
        return true;
    }

    const CpuMatrixSample* first_valid = nullptr;
    bool identity_uniform = true;
    bool structure_valid = true;
    for (u32 index = 0; index < sample_count; ++index) {
        const CpuMatrixSample& sample = samples[index];
        if (!IsCpuMatrixSampleValid(&sample)) {
            structure_valid = false;
            break;
        }
        if (!IsCpuMatrixSampleUsable(&sample)) {
            ++summary->invalid_count;
            continue;
        }
        if (first_valid == nullptr) {
            first_valid = &sample;
            summary->feature_intersection = sample.feature_flags;
            summary->feature_union = sample.feature_flags;
            summary->common_max_basic_leaf = sample.max_basic_leaf;
            summary->common_max_extended_leaf = sample.max_extended_leaf;
            summary->common_physical_address_bits =
                sample.physical_address_bits;
            summary->common_linear_address_bits = sample.linear_address_bits;
            summary->vendor_ebx = sample.vendor_ebx;
            summary->vendor_ecx = sample.vendor_ecx;
            summary->vendor_edx = sample.vendor_edx;
            continue;
        }
        summary->feature_intersection &= sample.feature_flags;
        summary->feature_union |= sample.feature_flags;
        if (!SameIdentity(*first_valid, sample)) identity_uniform = false;
        if (summary->common_max_basic_leaf != sample.max_basic_leaf)
            summary->common_max_basic_leaf = 0;
        if (summary->common_max_extended_leaf != sample.max_extended_leaf)
            summary->common_max_extended_leaf = 0;
        if (summary->common_physical_address_bits !=
            sample.physical_address_bits)
            summary->common_physical_address_bits = 0;
        if (summary->common_linear_address_bits != sample.linear_address_bits)
            summary->common_linear_address_bits = 0;
    }
    if (!structure_valid) {
        summary->state = static_cast<u32>(CpuMatrixState::Invalid);
        return false;
    }

    summary->valid_count = sample_count - summary->invalid_count;
    summary->inconsistent_features = summary->feature_union ^
                                     summary->feature_intersection;
    if (summary->valid_count != 0U &&
        (summary->feature_intersection & kCpuMatrixFeatureVmx) != 0) {
        summary->flags |= kCpuMatrixSummaryAllVmx;
    }
    if (summary->valid_count != 0U &&
        (summary->feature_intersection & kCpuMatrixFeatureInvariantTsc) != 0) {
        summary->flags |= kCpuMatrixSummaryAllInvariantTsc;
    }
    if ((summary->feature_union & kCpuMatrixFeatureHypervisor) != 0) {
        summary->flags |= kCpuMatrixSummaryAnyHypervisor;
    }
    if (identity_uniform && summary->valid_count != 0U) {
        summary->flags |= kCpuMatrixSummaryIdentityUniform;
    }
    if (summary->invalid_count != 0U) {
        summary->flags |= kCpuMatrixSummaryHasInvalidSamples;
    }
    if (summary->valid_count == expected_count &&
        sample_count == expected_count && expected_count != 0U) {
        summary->flags |= kCpuMatrixSummarySamplesComplete;
    }

    if (sample_count != expected_count || summary->invalid_count != 0U ||
        expected_count == 0U) {
        summary->state = static_cast<u32>(CpuMatrixState::Incomplete);
    } else if (!identity_uniform || summary->inconsistent_features != 0U) {
        summary->state = static_cast<u32>(CpuMatrixState::CompleteMixed);
    } else {
        summary->state = static_cast<u32>(CpuMatrixState::CompleteUniform);
    }
    return true;
}

bool IsCpuMatrixSummaryValid(const CpuMatrixSummary* summary) {
    if (summary == nullptr ||
        !IsVersionedSizeValid(summary->version, summary->size,
                              sizeof(CpuMatrixSummary)) ||
        !IsStateValid(summary->state) ||
        (summary->flags & ~kCpuMatrixKnownSummaryFlagMask) != 0 ||
        summary->sample_count > kCpuMatrixMaxProcessors ||
        summary->valid_count > summary->sample_count ||
        summary->invalid_count > summary->sample_count ||
        summary->valid_count + summary->invalid_count !=
            summary->sample_count ||
        (summary->feature_intersection & ~summary->feature_union) != 0 ||
        (summary->feature_intersection & ~kCpuMatrixKnownFeatureMask) != 0 ||
        (summary->feature_union & ~kCpuMatrixKnownFeatureMask) != 0 ||
        summary->inconsistent_features !=
            (summary->feature_union ^ summary->feature_intersection) ||
        summary->common_physical_address_bits > 52U ||
        summary->common_linear_address_bits > 64U ||
        summary->reserved[0] != 0 || summary->reserved[1] != 0 ||
        summary->reserved[2] != 0) {
        return false;
    }
    const auto state = static_cast<CpuMatrixState>(summary->state);
    if (state == CpuMatrixState::Empty) {
        return summary->expected_count == 0U && summary->sample_count == 0U &&
               summary->valid_count == 0U && summary->invalid_count == 0U;
    }
    if (state == CpuMatrixState::CompleteUniform ||
        state == CpuMatrixState::CompleteMixed) {
        return summary->expected_count == summary->sample_count &&
               summary->expected_count != 0U &&
               summary->invalid_count == 0U &&
               (summary->flags & kCpuMatrixSummarySamplesComplete) != 0;
    }
    return true;
}

bool IsCpuMatrixUniform(const CpuMatrixSummary* summary,
                        u64 required_features) {
    return IsCpuMatrixSummaryValid(summary) &&
           summary->state == static_cast<u32>(CpuMatrixState::CompleteUniform) &&
           (required_features & ~kCpuMatrixKnownFeatureMask) == 0 &&
           (summary->feature_intersection & required_features) ==
               required_features;
}

}  // namespace knhv
