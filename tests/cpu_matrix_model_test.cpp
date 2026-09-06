#include "test_support.h"

#include "knhv_cpu_matrix.h"

namespace knhv_tests {
namespace {

knhv::CpuMatrixSample MakeSample(std::uint32_t index,
                                 std::uint64_t features) {
    knhv::CpuMatrixSample sample = {};
    sample.size = sizeof(sample);
    sample.version = knhv::kCpuMatrixContractVersion;
    sample.logical_index = index;
    sample.processor_group = 0;
    sample.processor_number = index;
    sample.status = knhv::kCpuMatrixSampleCollected;
    sample.feature_flags = features;
    sample.max_basic_leaf = 0x1FU;
    sample.max_extended_leaf = 0x80000008U;
    sample.leaf7_max_subleaf = 2;
    sample.physical_address_bits = 48;
    sample.linear_address_bits = 57;
    sample.vendor_ebx = 0x756E6547U;
    sample.vendor_ecx = 0x6C65746EU;
    sample.vendor_edx = 0x49656E69U;
    sample.hypervisor_ebx = 0;
    sample.hypervisor_ecx = 0;
    sample.hypervisor_edx = 0;
    sample.leaf1_ecx = 0;
    sample.leaf1_edx = 0;
    sample.leaf7_ebx = 0;
    sample.leaf7_ecx = 0;
    sample.leaf7_edx = 0;
    sample.extended_leaf7_edx = 0;
    sample.extended_leaf8_eax = 0;
    return sample;
}

void CheckSampleValidation(TestState& state) {
    auto sample = MakeSample(
        0, knhv::kCpuMatrixFeatureVmx |
            knhv::kCpuMatrixFeatureInvariantTsc);
    Check(state, "CPU matrix accepts a collected sample",
          knhv::IsCpuMatrixSampleValid(&sample) &&
              knhv::IsCpuMatrixSampleUsable(&sample));
    auto null_sample = sample;
    null_sample.status = knhv::kCpuMatrixSampleAffinityFailed;
    Check(state, "CPU matrix keeps affinity failures structurally valid",
          knhv::IsCpuMatrixSampleValid(&null_sample) &&
              !knhv::IsCpuMatrixSampleUsable(&null_sample));
    auto unknown_feature = sample;
    unknown_feature.feature_flags |= 1ULL << 63;
    Check(state, "CPU matrix rejects unknown feature bits",
          !knhv::IsCpuMatrixSampleValid(&unknown_feature));
    auto bad_index = sample;
    bad_index.logical_index = knhv::kCpuMatrixMaxProcessors;
    Check(state, "CPU matrix rejects an out of range logical index",
          !knhv::IsCpuMatrixSampleValid(&bad_index));
}

void CheckSummaryStates(TestState& state) {
    knhv::CpuMatrixSample samples[2] = {
        MakeSample(0, knhv::kCpuMatrixFeatureVmx |
                          knhv::kCpuMatrixFeatureInvariantTsc),
        MakeSample(1, knhv::kCpuMatrixFeatureVmx |
                          knhv::kCpuMatrixFeatureInvariantTsc)};
    knhv::CpuMatrixSummary summary = {};
    Check(state, "CPU matrix builds a uniform complete summary",
          knhv::BuildCpuMatrixSummary(samples, 2, 2, &summary) &&
              summary.state == static_cast<std::uint32_t>(
                  knhv::CpuMatrixState::CompleteUniform) &&
              knhv::IsCpuMatrixUniform(
                  &summary, knhv::kCpuMatrixFeatureVmx |
                                knhv::kCpuMatrixFeatureInvariantTsc));
    samples[1].feature_flags |= knhv::kCpuMatrixFeatureInvpcid;
    Check(state, "CPU matrix reports mixed feature capabilities",
          knhv::BuildCpuMatrixSummary(samples, 2, 2, &summary) &&
              summary.state == static_cast<std::uint32_t>(
                  knhv::CpuMatrixState::CompleteMixed) &&
              !knhv::IsCpuMatrixUniform(&summary, 0));
    samples[1].status = knhv::kCpuMatrixSampleMigrated;
    Check(state, "CPU matrix reports an incomplete sample set",
          knhv::BuildCpuMatrixSummary(samples, 2, 2, &summary) &&
              summary.state == static_cast<std::uint32_t>(
                  knhv::CpuMatrixState::Incomplete) &&
              summary.invalid_count == 1);
    Check(state, "CPU matrix reports an empty expected set",
          knhv::BuildCpuMatrixSummary(nullptr, 0, 0, &summary) &&
              summary.state == static_cast<std::uint32_t>(
                  knhv::CpuMatrixState::Empty) &&
              knhv::IsCpuMatrixSummaryValid(&summary));
}

void CheckSummaryGuards(TestState& state) {
    auto sample = MakeSample(0, knhv::kCpuMatrixFeatureVmx);
    knhv::CpuMatrixSummary summary = {};
    Check(state, "CPU matrix rejects a null sample array for nonzero count",
          !knhv::BuildCpuMatrixSummary(nullptr, 1, 1, &summary));
    Check(state, "CPU matrix rejects a sample count beyond the bound",
          !knhv::BuildCpuMatrixSummary(&sample,
                                       knhv::kCpuMatrixMaxProcessors + 1U, 1,
                                       &summary));
    Check(state, "CPU matrix rejects a tampered summary",
          knhv::BuildCpuMatrixSummary(&sample, 1, 1, &summary) &&
              (summary.feature_union |= 1ULL << 63, true) &&
              !knhv::IsCpuMatrixSummaryValid(&summary));
}

}  // namespace

void RunCpuMatrixModelContract(TestState& state) {
    CheckSampleValidation(state);
    CheckSummaryStates(state);
    CheckSummaryGuards(state);
}

}  // namespace knhv_tests
