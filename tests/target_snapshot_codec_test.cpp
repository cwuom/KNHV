#include "test_support.h"

#include "knhv_target_snapshot_codec.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

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

knhv::CpuMatrixSample MakeCpuSample() {
    knhv::CpuMatrixSample sample{};
    sample.size = sizeof(sample);
    sample.version = knhv::kCpuMatrixContractVersion;
    sample.logical_index = 0U;
    sample.processor_number = 0U;
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

knhv::VmxCapabilitySample MakeVmxSample() {
    knhv::VmxCapabilitySample sample{};
    sample.size = sizeof(sample);
    sample.version = knhv::kVmxCapabilityContractVersion;
    sample.logical_index = 0U;
    sample.processor_number = 0U;
    sample.status = knhv::kVmxCapabilitySampleCollected;
    sample.generation = 23U;
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

knhv::TargetEvidenceSnapshot MakeInventorySnapshot() {
    knhv::TargetEvidenceSnapshot snapshot{};
    snapshot.size = sizeof(snapshot);
    snapshot.version = knhv::kTargetEvidenceSnapshotContractVersion;
    snapshot.profile = static_cast<std::uint32_t>(
        knhv::TargetEvidenceProfile::SyntheticLab);
    snapshot.stage = static_cast<std::uint32_t>(
        knhv::TargetEvidenceStage::Inventory);
    snapshot.verdict = static_cast<std::uint32_t>(
        knhv::TargetEvidenceVerdict::Ready);
    snapshot.flags = knhv::kTargetEvidenceSnapshotFlagSynthetic;
    return snapshot;
}

knhv::TargetEvidenceSnapshot MakeNativeCapability(
    const knhv::CpuMatrixSample& cpu_sample,
    const knhv::VmxCapabilitySample& vmx_sample) {
    knhv::TargetEvidenceSnapshot snapshot{};
    snapshot.size = sizeof(snapshot);
    snapshot.version = knhv::kTargetEvidenceSnapshotContractVersion;
    snapshot.profile = static_cast<std::uint32_t>(
        knhv::TargetEvidenceProfile::NativeIntelL0);
    snapshot.stage = static_cast<std::uint32_t>(
        knhv::TargetEvidenceStage::Capability);
    snapshot.verdict = static_cast<std::uint32_t>(
        knhv::TargetEvidenceVerdict::Pass);
    snapshot.flags = knhv::kTargetEvidenceSnapshotFlagCpuMatrix |
                     knhv::kTargetEvidenceSnapshotFlagVmxMatrix |
                     knhv::kTargetEvidenceSnapshotFlagHardwareEvidence;
    snapshot.generation = vmx_sample.generation;
    snapshot.started_tsc = 100U;
    snapshot.ended_tsc = 200U;
    knhv::BuildCpuMatrixSummary(&cpu_sample, 1U, 1U, &snapshot.cpu_matrix);
    knhv::BuildVmxCapabilityMatrix(&vmx_sample, 1U, 1U,
                                  &snapshot.vmx_matrix);
    FillDigest(snapshot.machine_id, 1U);
    FillDigest(snapshot.capability_hash, 2U);
    return snapshot;
}

knhv::TargetEvidenceSnapshotWireHeader ReadHeader(const knhv::u8* bytes) {
    knhv::TargetEvidenceSnapshotWireHeader header{};
    std::memcpy(&header, bytes, sizeof(header));
    return header;
}

void WriteHeader(knhv::u8* bytes,
                 const knhv::TargetEvidenceSnapshotWireHeader& header) {
    std::memcpy(bytes, &header, sizeof(header));
}

void CheckAbiAndSizing(TestState& state) {
    Check(state, "snapshot codec header ABI is fixed",
          sizeof(knhv::TargetEvidenceSnapshotWireHeader) == 64U &&
              knhv::kTargetEvidenceSnapshotWireHeaderSize == 64U);
    Check(state, "snapshot codec reports bounded package sizes",
          knhv::GetTargetEvidenceSnapshotWireSize(0U, 0U) == 640U &&
              knhv::GetTargetEvidenceSnapshotWireSize(
                  knhv::kCpuMatrixMaxProcessors + 1U, 0U) == 0U);
    const std::array<knhv::TargetEvidenceSnapshotCodecStatus, 9> statuses = {
        knhv::TargetEvidenceSnapshotCodecStatus::Success,
        knhv::TargetEvidenceSnapshotCodecStatus::InvalidArgument,
        knhv::TargetEvidenceSnapshotCodecStatus::BufferTooSmall,
        knhv::TargetEvidenceSnapshotCodecStatus::InvalidHeader,
        knhv::TargetEvidenceSnapshotCodecStatus::UnsupportedVersion,
        knhv::TargetEvidenceSnapshotCodecStatus::InvalidLength,
        knhv::TargetEvidenceSnapshotCodecStatus::SnapshotInvalid,
        knhv::TargetEvidenceSnapshotCodecStatus::DigestUnavailable,
        knhv::TargetEvidenceSnapshotCodecStatus::DigestMismatch};
    bool named = true;
    for (const auto status : statuses) {
        named = named && std::string(
                             knhv::TargetEvidenceSnapshotCodecStatusText(status)) !=
                         "unknown";
    }
    Check(state, "snapshot codec statuses have stable text", named);
}

void CheckInventoryRoundTrip(TestState& state) {
    const auto source = MakeInventorySnapshot();
    std::array<knhv::u8, 640> encoded{};
    knhv::u32 written = 0U;
    const auto encode_status = knhv::EncodeTargetEvidenceSnapshotPackage(
        &source, nullptr, 0U, nullptr, 0U, encoded.data(),
        static_cast<knhv::u32>(encoded.size()), &written);
    knhv::TargetEvidenceSnapshotWireHeader header{};
    const auto inspect_status = knhv::InspectTargetEvidenceSnapshotPackage(
        encoded.data(), written, &header);
    knhv::TargetEvidenceSnapshot decoded{};
    knhv::u32 cpu_count = 0U;
    knhv::u32 vmx_count = 0U;
    const auto decode_status = knhv::DecodeTargetEvidenceSnapshotPackage(
        encoded.data(), written, &decoded, nullptr, 0U, &cpu_count, nullptr,
        0U, &vmx_count);
    Check(state, "inventory snapshot round-trips without raw samples",
          encode_status == knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              written == encoded.size() &&
              inspect_status == knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              header.cpu_sample_count == 0U && header.vmx_sample_count == 0U &&
              decode_status == knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              std::memcmp(&source, &decoded, sizeof(source)) == 0 &&
              cpu_count == 0U && vmx_count == 0U);
}

void CheckNativeRoundTrip(TestState& state) {
    const auto cpu_source = MakeCpuSample();
    const auto vmx_source = MakeVmxSample();
    const auto source = MakeNativeCapability(cpu_source, vmx_source);
    const knhv::u32 expected_size =
        knhv::GetTargetEvidenceSnapshotWireSize(1U, 1U);
    std::vector<knhv::u8> encoded(expected_size);
    knhv::u32 written = 0U;
    const auto encode_status = knhv::EncodeTargetEvidenceSnapshotPackage(
        &source, &cpu_source, 1U, &vmx_source, 1U, encoded.data(),
        expected_size, &written);
    knhv::TargetEvidenceSnapshot decoded{};
    knhv::CpuMatrixSample cpu_decoded{};
    knhv::VmxCapabilitySample vmx_decoded{};
    knhv::u32 cpu_count = 0U;
    knhv::u32 vmx_count = 0U;
    const auto decode_status = knhv::DecodeTargetEvidenceSnapshotPackage(
        encoded.data(), written, &decoded, &cpu_decoded, 1U, &cpu_count,
        &vmx_decoded, 1U, &vmx_count);
    Check(state, "native capability snapshot round-trips raw samples",
          encode_status == knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              decode_status == knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              std::memcmp(&source, &decoded, sizeof(source)) == 0 &&
              std::memcmp(&cpu_source, &cpu_decoded, sizeof(cpu_source)) == 0 &&
              std::memcmp(&vmx_source, &vmx_decoded, sizeof(vmx_source)) == 0 &&
              cpu_count == 1U && vmx_count == 1U);
}

void CheckMalformedPackages(TestState& state) {
    const auto source = MakeInventorySnapshot();
    std::array<knhv::u8, 640> encoded{};
    knhv::u32 written = 0U;
    (void)knhv::EncodeTargetEvidenceSnapshotPackage(
        &source, nullptr, 0U, nullptr, 0U, encoded.data(),
        static_cast<knhv::u32>(encoded.size()), &written);

    auto tampered = encoded;
    tampered[64] ^= 1U;
    knhv::TargetEvidenceSnapshot decoded{};
    knhv::u32 cpu_count = 0U;
    knhv::u32 vmx_count = 0U;
    Check(state, "snapshot codec rejects payload tampering",
          knhv::DecodeTargetEvidenceSnapshotPackage(
              tampered.data(), written, &decoded, nullptr, 0U, &cpu_count,
              nullptr, 0U, &vmx_count) ==
              knhv::TargetEvidenceSnapshotCodecStatus::DigestMismatch);

    auto bad_version = encoded;
    knhv::TargetEvidenceSnapshotWireHeader version_header{};
    std::memcpy(&version_header, bad_version.data(), sizeof(version_header));
    version_header.version = 2U;
    std::memcpy(bad_version.data(), &version_header, sizeof(version_header));
    Check(state, "snapshot codec rejects an unsupported version",
          knhv::InspectTargetEvidenceSnapshotPackage(
              bad_version.data(), written, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::UnsupportedVersion);

    auto bad_magic = encoded;
    auto magic_header = ReadHeader(bad_magic.data());
    magic_header.magic[0] ^= 1U;
    WriteHeader(bad_magic.data(), magic_header);
    Check(state, "snapshot codec rejects an invalid magic",
          knhv::InspectTargetEvidenceSnapshotPackage(
              bad_magic.data(), written, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidHeader);

    auto bad_reserved = encoded;
    auto reserved_header = ReadHeader(bad_reserved.data());
    reserved_header.reserved2 = 1U;
    WriteHeader(bad_reserved.data(), reserved_header);
    Check(state, "snapshot codec rejects nonzero reserved fields",
          knhv::InspectTargetEvidenceSnapshotPackage(
              bad_reserved.data(), written, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidHeader);

    auto bad_count = encoded;
    auto count_header = ReadHeader(bad_count.data());
    count_header.cpu_sample_count = knhv::kCpuMatrixMaxProcessors + 1U;
    WriteHeader(bad_count.data(), count_header);
    Check(state, "snapshot codec rejects sample count overflow",
          knhv::InspectTargetEvidenceSnapshotPackage(
              bad_count.data(), written, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidLength);

    auto bad_payload = encoded;
    auto payload_header = ReadHeader(bad_payload.data());
    payload_header.payload_size += 1U;
    WriteHeader(bad_payload.data(), payload_header);
    Check(state, "snapshot codec rejects payload length mismatch",
          knhv::InspectTargetEvidenceSnapshotPackage(
              bad_payload.data(), written, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidLength);

    auto bad_envelope = encoded;
    auto envelope_header = ReadHeader(bad_envelope.data());
    envelope_header.envelope_size += 1U;
    WriteHeader(bad_envelope.data(), envelope_header);
    Check(state, "snapshot codec rejects envelope length mismatch",
          knhv::InspectTargetEvidenceSnapshotPackage(
              bad_envelope.data(), written, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidLength);

    knhv::TargetEvidenceSnapshotWireHeader cleared_header{};
    cleared_header.version = 99U;
    const auto inspect_argument_status =
        knhv::InspectTargetEvidenceSnapshotPackage(
            nullptr, 0U, &cleared_header);
    bool header_cleared = true;
    const auto zero_header = knhv::TargetEvidenceSnapshotWireHeader{};
    header_cleared =
        std::memcmp(&cleared_header, &zero_header, sizeof(zero_header)) == 0;
    Check(state, "snapshot codec clears inspect output on invalid input",
          inspect_argument_status ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidArgument &&
              header_cleared);

    Check(state, "snapshot codec rejects input above the package limit",
          knhv::InspectTargetEvidenceSnapshotPackage(
              encoded.data(), knhv::kTargetEvidenceSnapshotWireMaxSize + 1U,
              &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidLength);

    Check(state, "snapshot codec rejects truncation",
          knhv::InspectTargetEvidenceSnapshotPackage(
              encoded.data(), written - 1U, &version_header) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidLength);

    Check(state, "snapshot codec rejects a short output buffer",
          knhv::EncodeTargetEvidenceSnapshotPackage(
              &source, nullptr, 0U, nullptr, 0U, encoded.data(), 639U,
              &written) ==
              knhv::TargetEvidenceSnapshotCodecStatus::BufferTooSmall);

    auto invalid = source;
    invalid.flags |= knhv::kTargetEvidenceSnapshotFlagHardwareEvidence;
    Check(state, "snapshot codec validates the embedded snapshot",
          knhv::EncodeTargetEvidenceSnapshotPackage(
              &invalid, nullptr, 0U, nullptr, 0U, encoded.data(),
              static_cast<knhv::u32>(encoded.size()), &written) ==
              knhv::TargetEvidenceSnapshotCodecStatus::SnapshotInvalid);
}

void CheckDecodeCapacityAndArguments(TestState& state) {
    const auto source = MakeInventorySnapshot();
    std::array<knhv::u8, 640> encoded{};
    knhv::u32 written = 0U;
    (void)knhv::EncodeTargetEvidenceSnapshotPackage(
        &source, nullptr, 0U, nullptr, 0U, encoded.data(),
        static_cast<knhv::u32>(encoded.size()), &written);
    knhv::TargetEvidenceSnapshot decoded{};
    knhv::u32 cpu_count = 9U;
    knhv::u32 vmx_count = 9U;
    Check(state, "snapshot codec clears decode counters after malformed input",
          knhv::DecodeTargetEvidenceSnapshotPackage(
              nullptr, written, &decoded, nullptr, 0U, &cpu_count, nullptr,
              0U, &vmx_count) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidArgument &&
              cpu_count == 0U && vmx_count == 0U);
    Check(state, "snapshot codec rejects missing output counters",
          knhv::DecodeTargetEvidenceSnapshotPackage(
              encoded.data(), written, &decoded, nullptr, 0U, nullptr, nullptr,
              0U, &vmx_count) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidArgument &&
              vmx_count == 0U);

    const auto cpu_source = MakeCpuSample();
    const auto vmx_source = MakeVmxSample();
    const auto native_source = MakeNativeCapability(cpu_source, vmx_source);
    const knhv::u32 native_size =
        knhv::GetTargetEvidenceSnapshotWireSize(1U, 1U);
    std::vector<knhv::u8> native_encoded(native_size);
    knhv::u32 native_written = 0U;
    const auto native_encode_status =
        knhv::EncodeTargetEvidenceSnapshotPackage(
            &native_source, &cpu_source, 1U, &vmx_source, 1U,
            native_encoded.data(), native_size, &native_written);
    knhv::CpuMatrixSample cpu_output{};
    knhv::VmxCapabilitySample vmx_output{};
    knhv::u32 native_cpu_count = 7U;
    knhv::u32 native_vmx_count = 7U;
    knhv::TargetEvidenceSnapshot native_decoded{};
    std::memset(&native_decoded, 0xA5, sizeof(native_decoded));
    const auto capacity_status =
        knhv::DecodeTargetEvidenceSnapshotPackage(
            native_encoded.data(), native_written, &native_decoded,
            &cpu_output, 0U, &native_cpu_count, &vmx_output, 0U,
            &native_vmx_count);
    const auto zero_snapshot = knhv::TargetEvidenceSnapshot{};
    Check(state, "snapshot codec fails closed on raw sample capacity",
          native_encode_status ==
              knhv::TargetEvidenceSnapshotCodecStatus::Success &&
              capacity_status ==
                  knhv::TargetEvidenceSnapshotCodecStatus::BufferTooSmall &&
              native_cpu_count == 0U && native_vmx_count == 0U &&
              std::memcmp(&native_decoded, &zero_snapshot,
                          sizeof(zero_snapshot)) == 0);

    knhv::u32 null_snapshot_cpu_count = 5U;
    knhv::u32 null_snapshot_vmx_count = 6U;
    Check(state, "snapshot codec clears counters with a null snapshot",
          knhv::DecodeTargetEvidenceSnapshotPackage(
              encoded.data(), written, nullptr, nullptr, 0U,
              &null_snapshot_cpu_count, nullptr, 0U,
              &null_snapshot_vmx_count) ==
              knhv::TargetEvidenceSnapshotCodecStatus::InvalidArgument &&
              null_snapshot_cpu_count == 0U && null_snapshot_vmx_count == 0U);
}

}  // namespace

void RunTargetEvidenceSnapshotCodecContract(TestState& state) {
    CheckAbiAndSizing(state);
    CheckInventoryRoundTrip(state);
    CheckNativeRoundTrip(state);
    CheckMalformedPackages(state);
    CheckDecodeCapacityAndArguments(state);
}

}  // namespace knhv_tests
