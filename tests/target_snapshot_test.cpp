#include "test_support.h"

#include "knhv_target_snapshot.h"

#include <array>
#include <cstdint>
#include <string>

namespace knhv_tests {
namespace {

void FillDigest(knhv::u8 (&digest)[32], knhv::u8 value) {
    for (knhv::u8& byte : digest) byte = value;
}

knhv::VmxControlCapability PairCapability(std::uint32_t allowed) {
    knhv::VmxControlCapability capability{};
    capability.size = sizeof(capability);
    capability.version = knhv::kVmxCapabilityContractVersion;
    capability.encoding = static_cast<std::uint32_t>(
        knhv::VmxControlEncoding::Pair32);
    capability.allowed_one = allowed;
    return capability;
}

knhv::VmxControlCapability TertiaryCapability(std::uint64_t allowed) {
    knhv::VmxControlCapability capability{};
    capability.size = sizeof(capability);
    capability.version = knhv::kVmxCapabilityContractVersion;
    capability.encoding = static_cast<std::uint32_t>(
        knhv::VmxControlEncoding::AllowedOne64);
    capability.allowed_one = allowed;
    return capability;
}

knhv::CpuMatrixSample MakeCpuSample(std::uint32_t index) {
    knhv::CpuMatrixSample sample{};
    sample.size = sizeof(sample);
    sample.version = knhv::kCpuMatrixContractVersion;
    sample.logical_index = index;
    sample.processor_number = index;
    sample.status = knhv::kCpuMatrixSampleCollected;
    sample.feature_flags = knhv::kCpuMatrixFeatureVmx |
                           knhv::kCpuMatrixFeatureInvariantTsc;
    sample.max_basic_leaf = 0x1FU;
    sample.max_extended_leaf = 0x80000008U;
    sample.leaf7_max_subleaf = 2U;
    sample.physical_address_bits = 48U;
    sample.linear_address_bits = 57U;
    sample.vendor_ebx = 0x756E6547U;
    sample.vendor_ecx = 0x6C65746EU;
    sample.vendor_edx = 0x49656E69U;
    return sample;
}

knhv::VmxCapabilitySample MakeVmxSample(std::uint32_t index,
                                        std::uint64_t generation) {
    knhv::VmxCapabilitySample sample{};
    sample.size = sizeof(sample);
    sample.version = knhv::kVmxCapabilityContractVersion;
    sample.logical_index = index;
    sample.processor_number = index;
    sample.status = knhv::kVmxCapabilitySampleCollected;
    sample.generation = generation;
    sample.vmx_basic = 1ULL | knhv::kVmxBasicTrueControls;
    sample.feature_control = knhv::kVmxFeatureControlLock |
                             knhv::kVmxFeatureControlVmxonOutsideSmx;
    sample.ept_vpid_cap = knhv::kVmxEptVpidCapBasicEpt |
                          knhv::kVmxEptVpidCapFullInvept |
                          knhv::kVmxEptVpidCapFullInvvpid;
    sample.pin_controls = PairCapability(0xFFFFFFFFU);
    sample.primary_controls = PairCapability(0xFFFFFFFFU);
    sample.secondary_controls = PairCapability(0xFFFFFFFFU);
    sample.tertiary_controls = TertiaryCapability(~0ULL);
    sample.exit_controls = PairCapability(0xFFFFFFFFU);
    sample.entry_controls = PairCapability(0xFFFFFFFFU);
    sample.cr0_fixed1 = ~0ULL;
    sample.cr4_fixed1 = ~0ULL;
    return sample;
}

knhv::OwnerObservation MakeOwnerObservation(knhv::HvOwnerKindV2 owner,
                                             knhv::HvProviderStateV2 state,
                                             std::uint64_t generation) {
    knhv::OwnerObservation observation{};
    observation.size = sizeof(observation);
    observation.version = knhv::kOwnerObservationContractVersion;
    observation.cpuid_hypervisor = static_cast<std::uint32_t>(
        owner == knhv::HvOwnerKindV2::ExternalL0
            ? knhv::OwnerEvidenceState::Present
            : knhv::OwnerEvidenceState::Clear);
    observation.windows_hypervisor = static_cast<std::uint32_t>(
        owner == knhv::HvOwnerKindV2::WhpManaged
            ? knhv::OwnerEvidenceState::Present
            : knhv::OwnerEvidenceState::Clear);
    observation.vbs = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    observation.hvci = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Clear);
    observation.whp_available = static_cast<std::uint32_t>(
        owner == knhv::HvOwnerKindV2::WhpManaged
            ? knhv::OwnerEvidenceState::Present
            : knhv::OwnerEvidenceState::Clear);
    observation.provider_device = static_cast<std::uint32_t>(
        knhv::OwnerEvidenceState::Present);
    observation.boot_handoff = static_cast<std::uint32_t>(
        owner == knhv::HvOwnerKindV2::KnhvBootL0
            ? knhv::OwnerEvidenceState::Present
            : knhv::OwnerEvidenceState::Clear);
    observation.provider_owner = static_cast<std::uint32_t>(owner);
    observation.provider_state = static_cast<std::uint32_t>(state);
    observation.generation = generation;
    return observation;
}

knhv::TargetEvidenceSnapshot MakeSnapshot(
    knhv::TargetEvidenceProfile profile,
    knhv::TargetEvidenceStage stage = knhv::TargetEvidenceStage::Release,
    knhv::TargetEvidenceVerdict verdict =
        knhv::TargetEvidenceVerdict::Pass) {
    knhv::TargetEvidenceSnapshot snapshot{};
    snapshot.size = sizeof(snapshot);
    snapshot.version = knhv::kTargetEvidenceSnapshotContractVersion;
    snapshot.profile = static_cast<std::uint32_t>(profile);
    snapshot.stage = static_cast<std::uint32_t>(stage);
    snapshot.verdict = static_cast<std::uint32_t>(verdict);
    snapshot.generation = 19U;
    snapshot.started_tsc = 100U;
    snapshot.ended_tsc = 200U;
    if (profile == knhv::TargetEvidenceProfile::SyntheticLab) {
        snapshot.flags |= knhv::kTargetEvidenceSnapshotFlagSynthetic;
    }
    return snapshot;
}

void AddCommonHashes(knhv::TargetEvidenceSnapshot& snapshot) {
    FillDigest(snapshot.build_id, 2U);
    FillDigest(snapshot.artifact_hash, 3U);
    FillDigest(snapshot.capability_hash, 4U);
    FillDigest(snapshot.manifest_hash, 5U);
}

knhv::TargetEvidenceSnapshot MakeSyntheticRelease() {
    auto snapshot = MakeSnapshot(knhv::TargetEvidenceProfile::SyntheticLab);
    snapshot.flags |= knhv::kTargetEvidenceSnapshotFlagOwnerObservation |
                      knhv::kTargetEvidenceSnapshotFlagOwnerGate |
                      knhv::kTargetEvidenceSnapshotFlagArtifacts |
                      knhv::kTargetEvidenceSnapshotFlagSourceClean |
                      knhv::kTargetEvidenceSnapshotFlagTimeSynchronized |
                      knhv::kTargetEvidenceSnapshotFlagTelemetry |
                      knhv::kTargetEvidenceSnapshotFlagRecoveryReady |
                      knhv::kTargetEvidenceSnapshotFlagSignature |
                      knhv::kTargetEvidenceSnapshotFlagNoCriticalFaults |
                      knhv::kTargetEvidenceSnapshotFlagPerformance |
                      knhv::kTargetEvidenceSnapshotFlagWarningsClear |
                      knhv::kTargetEvidenceSnapshotFlagAllowPrivateTestRoot;
    snapshot.artifact_count = 1U;
    FillDigest(snapshot.build_id, 2U);
    FillDigest(snapshot.artifact_hash, 3U);
    FillDigest(snapshot.manifest_hash, 5U);
    snapshot.owner_observation = MakeOwnerObservation(
        knhv::HvOwnerKindV2::SyntheticLab,
        knhv::HvProviderStateV2::Active, snapshot.generation);
    knhv::EvaluateOwnerGate(&snapshot.owner_observation, &snapshot.owner_gate);
    snapshot.signature.size = sizeof(snapshot.signature);
    snapshot.signature.version =
        knhv::kTargetEvidenceSignatureContractVersion;
    snapshot.signature.status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot);
    snapshot.signature.wintrust_status = 1U;
    snapshot.signature.result_flags =
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted;
    return snapshot;
}

knhv::TargetEvidenceSnapshot MakeNativeCapability(
    const std::array<knhv::CpuMatrixSample, 2>& cpu_samples,
    const std::array<knhv::VmxCapabilitySample, 2>& vmx_samples) {
    auto snapshot = MakeSnapshot(knhv::TargetEvidenceProfile::NativeIntelL0,
                                 knhv::TargetEvidenceStage::Capability);
    snapshot.flags |= knhv::kTargetEvidenceSnapshotFlagCpuMatrix |
                      knhv::kTargetEvidenceSnapshotFlagVmxMatrix |
                      knhv::kTargetEvidenceSnapshotFlagHardwareEvidence;
    snapshot.cpu_matrix = {};
    snapshot.vmx_matrix = {};
    knhv::BuildCpuMatrixSummary(cpu_samples.data(),
                                static_cast<std::uint32_t>(cpu_samples.size()),
                                static_cast<std::uint32_t>(cpu_samples.size()),
                                &snapshot.cpu_matrix);
    knhv::BuildVmxCapabilityMatrix(
        vmx_samples.data(), static_cast<std::uint32_t>(vmx_samples.size()),
        static_cast<std::uint32_t>(vmx_samples.size()), &snapshot.vmx_matrix);
    FillDigest(snapshot.machine_id, 1U);
    FillDigest(snapshot.capability_hash, 4U);
    return snapshot;
}

knhv::TargetEvidenceSnapshot MakeNativeRelease(
    const std::array<knhv::CpuMatrixSample, 2>& cpu_samples,
    const std::array<knhv::VmxCapabilitySample, 2>& vmx_samples) {
    auto snapshot = MakeSnapshot(knhv::TargetEvidenceProfile::NativeIntelL0);
    snapshot.flags |= knhv::kTargetEvidenceSnapshotFlagCpuMatrix |
                      knhv::kTargetEvidenceSnapshotFlagVmxMatrix |
                      knhv::kTargetEvidenceSnapshotFlagOwnerObservation |
                      knhv::kTargetEvidenceSnapshotFlagOwnerGate |
                      knhv::kTargetEvidenceSnapshotFlagHardwareEvidence |
                      knhv::kTargetEvidenceSnapshotFlagArtifacts |
                      knhv::kTargetEvidenceSnapshotFlagSourceClean |
                      knhv::kTargetEvidenceSnapshotFlagTimeSynchronized |
                      knhv::kTargetEvidenceSnapshotFlagTelemetry |
                      knhv::kTargetEvidenceSnapshotFlagRecoveryReady |
                      knhv::kTargetEvidenceSnapshotFlagSignature |
                      knhv::kTargetEvidenceSnapshotFlagKdConnected |
                      knhv::kTargetEvidenceSnapshotFlagDeviceProfiles |
                      knhv::kTargetEvidenceSnapshotFlagPerformance |
                      knhv::kTargetEvidenceSnapshotFlagNoCriticalFaults |
                      knhv::kTargetEvidenceSnapshotFlagWarningsClear;
    snapshot.artifact_count = 2U;
    knhv::BuildCpuMatrixSummary(cpu_samples.data(),
                                static_cast<std::uint32_t>(cpu_samples.size()),
                                static_cast<std::uint32_t>(cpu_samples.size()),
                                &snapshot.cpu_matrix);
    knhv::BuildVmxCapabilityMatrix(
        vmx_samples.data(), static_cast<std::uint32_t>(vmx_samples.size()),
        static_cast<std::uint32_t>(vmx_samples.size()), &snapshot.vmx_matrix);
    snapshot.owner_observation = MakeOwnerObservation(
        knhv::HvOwnerKindV2::KnhvBootL0, knhv::HvProviderStateV2::Active,
        snapshot.generation);
    knhv::EvaluateOwnerGate(&snapshot.owner_observation, &snapshot.owner_gate);
    FillDigest(snapshot.machine_id, 1U);
    AddCommonHashes(snapshot);
    snapshot.signature.size = sizeof(snapshot.signature);
    snapshot.signature.version =
        knhv::kTargetEvidenceSignatureContractVersion;
    snapshot.signature.status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceSignatureStatus::Trusted);
    return snapshot;
}

void CheckAbiAndText(TestState& state) {
    Check(state, "target snapshot ABI is fixed",
          sizeof(knhv::TargetEvidenceSnapshot) == 544U &&
              sizeof(knhv::TargetEvidenceSnapshotResult) == 280U);
    const std::array<knhv::TargetEvidenceSnapshotStatus, 12> statuses = {
        knhv::TargetEvidenceSnapshotStatus::Success,
        knhv::TargetEvidenceSnapshotStatus::InvalidArgument,
        knhv::TargetEvidenceSnapshotStatus::CpuEvidenceInvalid,
        knhv::TargetEvidenceSnapshotStatus::VmxEvidenceInvalid,
        knhv::TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid,
        knhv::TargetEvidenceSnapshotStatus::GenerationMismatch,
        knhv::TargetEvidenceSnapshotStatus::CoverageIncomplete,
        knhv::TargetEvidenceSnapshotStatus::ProfileMismatch,
        knhv::TargetEvidenceSnapshotStatus::TimestampInvalid,
        knhv::TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing,
        knhv::TargetEvidenceSnapshotStatus::SignatureEvidenceMissing,
        knhv::TargetEvidenceSnapshotStatus::WriterRejected};
    bool named = true;
    for (const auto status : statuses) {
        named = named && std::string(
                             knhv::TargetEvidenceSnapshotStatusText(status)) !=
                         "unknown";
    }
    Check(state, "target snapshot statuses have stable text", named);
}

void CheckSyntheticPath(TestState& state) {
    auto snapshot = MakeSyntheticRelease();
    knhv::TargetEvidenceSnapshotResult result{};
    Check(state, "synthetic snapshot reaches the manifest writer",
          knhv::IsTargetEvidenceSnapshotValid(&snapshot, nullptr, 0U, nullptr,
                                              0U) &&
              knhv::BuildTargetEvidenceManifestFromSnapshot(
                  &snapshot, nullptr, 0U, nullptr, 0U, &result) &&
              result.status == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceSnapshotStatus::Success) &&
              result.writer_status == static_cast<std::uint32_t>(
                                          knhv::TargetEvidenceWriterStatus::
                                              Success) &&
              knhv::IsTargetEvidenceSnapshotResultValid(&result));

    auto hardware = snapshot;
    hardware.flags |= knhv::kTargetEvidenceSnapshotFlagHardwareEvidence;
    Check(state, "synthetic snapshot rejects a hardware claim",
          knhv::ValidateTargetEvidenceSnapshot(&hardware, nullptr, 0U, nullptr,
                                               0U) ==
              knhv::TargetEvidenceSnapshotStatus::ProfileMismatch);
}

void CheckMatrixPath(TestState& state) {
    const std::array<knhv::CpuMatrixSample, 2> cpu_samples = {
        MakeCpuSample(0U), MakeCpuSample(1U)};
    const std::array<knhv::VmxCapabilitySample, 2> vmx_samples = {
        MakeVmxSample(0U, 19U), MakeVmxSample(1U, 19U)};
    auto snapshot = MakeNativeCapability(cpu_samples, vmx_samples);
    knhv::TargetEvidenceSnapshotResult result{};
    Check(state, "native capability snapshot verifies both sample sets",
          knhv::IsTargetEvidenceSnapshotValid(
              &snapshot, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()),
              vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size())) &&
              knhv::BuildTargetEvidenceManifestFromSnapshot(
                  &snapshot, cpu_samples.data(),
                  static_cast<std::uint32_t>(cpu_samples.size()),
                  vmx_samples.data(),
                  static_cast<std::uint32_t>(vmx_samples.size()), &result) &&
              result.status == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceSnapshotStatus::Success) &&
              (result.manifest.flags &
               knhv::kTargetEvidenceFlagCapabilityComplete) != 0U);

    auto cpu_tampered = snapshot;
    cpu_tampered.cpu_matrix.feature_union |= 1ULL << 63;
    Check(state, "snapshot rejects a forged CPU summary",
          knhv::ValidateTargetEvidenceSnapshot(
              &cpu_tampered, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()), vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size())) ==
              knhv::TargetEvidenceSnapshotStatus::CpuEvidenceInvalid);

    auto vmx_tampered = snapshot;
    vmx_tampered.vmx_matrix.generation = 20U;
    Check(state, "snapshot rejects a forged VMX summary",
          knhv::ValidateTargetEvidenceSnapshot(
              &vmx_tampered, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()), vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size())) ==
              knhv::TargetEvidenceSnapshotStatus::VmxEvidenceInvalid);

    Check(state, "snapshot requires raw samples for a present CPU matrix",
          knhv::ValidateTargetEvidenceSnapshot(&snapshot, nullptr, 0U,
                                               vmx_samples.data(),
                                               static_cast<std::uint32_t>(
                                                   vmx_samples.size())) ==
              knhv::TargetEvidenceSnapshotStatus::CpuEvidenceInvalid);

    auto stale = snapshot;
    stale.generation = 20U;
    Check(state, "snapshot binds VMX evidence to one generation",
          knhv::ValidateTargetEvidenceSnapshot(
              &stale, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()), vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size())) ==
              knhv::TargetEvidenceSnapshotStatus::GenerationMismatch);
}

void CheckReleaseAndOwnerPath(TestState& state) {
    const std::array<knhv::CpuMatrixSample, 2> cpu_samples = {
        MakeCpuSample(0U), MakeCpuSample(1U)};
    const std::array<knhv::VmxCapabilitySample, 2> vmx_samples = {
        MakeVmxSample(0U, 19U), MakeVmxSample(1U, 19U)};
    auto snapshot = MakeNativeRelease(cpu_samples, vmx_samples);
    knhv::TargetEvidenceSnapshotResult result{};
    Check(state, "native release snapshot closes every evidence dependency",
          knhv::BuildTargetEvidenceManifestFromSnapshot(
              &snapshot, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()),
              vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size()), &result) &&
              result.status == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceSnapshotStatus::Success) &&
              result.writer_status == static_cast<std::uint32_t>(
                                          knhv::TargetEvidenceWriterStatus::
                                              Success) &&
              knhv::IsTargetEvidenceSnapshotResultValid(&result));

    auto missing = snapshot;
    missing.flags &= ~knhv::kTargetEvidenceSnapshotFlagRecoveryReady;
    Check(state, "native release blocks missing recovery evidence",
          knhv::ValidateTargetEvidenceSnapshot(
              &missing, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()), vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size())) ==
              knhv::TargetEvidenceSnapshotStatus::CoverageIncomplete);

    auto wrong_owner = snapshot;
    wrong_owner.owner_gate.owner = static_cast<std::uint32_t>(
        knhv::HvOwnerKindV2::ExternalL0);
    Check(state, "native release rejects a mismatched owner gate",
          knhv::ValidateTargetEvidenceSnapshot(
              &wrong_owner, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()), vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size())) ==
              knhv::TargetEvidenceSnapshotStatus::OwnerEvidenceInvalid);

    auto private_root = snapshot;
    private_root.signature.status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceSignatureStatus::PrivateTestRoot);
    private_root.signature.wintrust_status = 1U;
    private_root.signature.result_flags =
        knhv::kTargetEvidenceSignatureResultPrivateRootAccepted;
    knhv::TargetEvidenceSnapshotResult blocked{};
    Check(state, "native release rejects a private test root",
          knhv::BuildTargetEvidenceManifestFromSnapshot(
              &private_root, cpu_samples.data(),
              static_cast<std::uint32_t>(cpu_samples.size()), vmx_samples.data(),
              static_cast<std::uint32_t>(vmx_samples.size()), &blocked) &&
              blocked.status == static_cast<std::uint32_t>(
                                    knhv::TargetEvidenceSnapshotStatus::
                                        WriterRejected) &&
              blocked.writer_status == static_cast<std::uint32_t>(
                                           knhv::TargetEvidenceWriterStatus::
                                               SignatureUntrusted));
}

void CheckMalformedSnapshot(TestState& state) {
    auto snapshot = MakeSyntheticRelease();
    auto bad_flags = snapshot;
    bad_flags.flags |= 1U << 31;
    Check(state, "snapshot rejects unknown flags",
          knhv::ValidateTargetEvidenceSnapshot(&bad_flags, nullptr, 0U,
                                               nullptr, 0U) ==
              knhv::TargetEvidenceSnapshotStatus::InvalidArgument);

    auto bad_timestamp = snapshot;
    bad_timestamp.started_tsc = 300U;
    bad_timestamp.ended_tsc = 200U;
    Check(state, "snapshot rejects a backwards timestamp",
          knhv::ValidateTargetEvidenceSnapshot(&bad_timestamp, nullptr, 0U,
                                               nullptr, 0U) ==
              knhv::TargetEvidenceSnapshotStatus::TimestampInvalid);

    auto bad_artifact = snapshot;
    FillDigest(bad_artifact.artifact_hash, 0U);
    Check(state, "snapshot rejects an artifact flag without a hash",
          knhv::ValidateTargetEvidenceSnapshot(&bad_artifact, nullptr, 0U,
                                               nullptr, 0U) ==
              knhv::TargetEvidenceSnapshotStatus::ArtifactEvidenceMissing);

    knhv::TargetEvidenceSnapshotResult forged{};
    forged.size = sizeof(forged);
    forged.version = knhv::kTargetEvidenceSnapshotContractVersion;
    forged.status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceSnapshotStatus::Success);
    forged.writer_status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceWriterStatus::Success);
    Check(state, "snapshot result rejects a forged success",
          !knhv::IsTargetEvidenceSnapshotResultValid(&forged));

    forged.status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceSnapshotStatus::WriterRejected);
    forged.reason = static_cast<std::uint32_t>(
        knhv::TargetEvidenceReason::SignatureUnverified);
    forged.writer_status = static_cast<std::uint32_t>(
        knhv::TargetEvidenceWriterStatus::SignatureUntrusted);
    forged.manifest.version = knhv::kTargetEvidenceContractVersion;
    Check(state, "snapshot result rejects a partial manifest",
          !knhv::IsTargetEvidenceSnapshotResultValid(&forged));
}

void CheckInventoryPath(TestState& state) {
    auto inventory = MakeSnapshot(knhv::TargetEvidenceProfile::SyntheticLab,
                                  knhv::TargetEvidenceStage::Inventory,
                                  knhv::TargetEvidenceVerdict::Ready);
    inventory.generation = 0U;
    knhv::TargetEvidenceSnapshotResult result{};
    Check(state, "inventory snapshot remains unsigned and hardware-free",
          knhv::BuildTargetEvidenceManifestFromSnapshot(
              &inventory, nullptr, 0U, nullptr, 0U, &result) &&
              result.status == static_cast<std::uint32_t>(
                                   knhv::TargetEvidenceSnapshotStatus::Success) &&
              result.manifest.generation == 0U);
}

}  // namespace

void RunTargetEvidenceSnapshotContract(TestState& state) {
    CheckAbiAndText(state);
    CheckSyntheticPath(state);
    CheckMatrixPath(state);
    CheckReleaseAndOwnerPath(state);
    CheckMalformedSnapshot(state);
    CheckInventoryPath(state);
}

}  // namespace knhv_tests
