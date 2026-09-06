#include "test_support.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "knhv_target_evidence_codec.h"

namespace knhv_tests {
namespace {

void FillDigest(knhv::u8* digest, knhv::u8 seed) {
    for (knhv::u32 index = 0U; index < 32U; ++index) {
        digest[index] = static_cast<knhv::u8>(seed + index);
    }
}

knhv::TargetEvidenceManifest MakeSyntheticManifest() {
    knhv::TargetEvidenceManifest manifest{};
    manifest.size = sizeof(manifest);
    manifest.version = knhv::kTargetEvidenceContractVersion;
    manifest.profile = static_cast<knhv::u32>(
        knhv::TargetEvidenceProfile::SyntheticLab);
    manifest.stage = static_cast<knhv::u32>(knhv::TargetEvidenceStage::Release);
    manifest.verdict = static_cast<knhv::u32>(
        knhv::TargetEvidenceVerdict::Pass);
    manifest.flags = knhv::RequiredTargetEvidenceFlags(
        knhv::TargetEvidenceProfile::SyntheticLab,
        knhv::TargetEvidenceStage::Release);
    manifest.owner_kind = static_cast<knhv::u32>(
        knhv::HvOwnerKindV2::SyntheticLab);
    manifest.owner_state = static_cast<knhv::u32>(
        knhv::HvProviderStateV2::Active);
    manifest.cpu_count = 1U;
    manifest.cpu_valid_count = 1U;
    manifest.artifact_count = 1U;
    manifest.generation = 42U;
    manifest.started_tsc = 100U;
    manifest.ended_tsc = 200U;
    FillDigest(manifest.build_id, 1U);
    FillDigest(manifest.artifact_hash, 2U);
    FillDigest(manifest.capability_hash, 3U);
    FillDigest(manifest.manifest_hash, 4U);
    return manifest;
}

bool MarkerVerifier(const knhv::u8* content, knhv::u32 content_size,
                    const knhv::u8* signature, knhv::u32 signature_size,
                    void*) {
    return content != nullptr && content_size >= 8U && signature != nullptr &&
           signature_size == 3U &&
           std::memcmp(signature, "ok!", signature_size) == 0 &&
           content[0] == static_cast<knhv::u8>('K');
}

void CheckRoundTrip(TestState& state) {
    const knhv::TargetEvidenceManifest source = MakeSyntheticManifest();
    std::array<knhv::u8, knhv::kTargetEvidenceWireEnvelopeSize> package{};
    knhv::u32 written = 0U;
    const auto encode_status = knhv::EncodeTargetEvidencePackage(
        &source, package.data(), static_cast<knhv::u32>(package.size()),
        &written);
    Check(state, "evidence codec emits the fixed envelope",
          encode_status == knhv::TargetEvidenceCodecStatus::Success &&
              written == package.size());

    knhv::TargetEvidenceManifest decoded{};
    const auto decode_status = knhv::DecodeTargetEvidencePackage(
        package.data(), written, &decoded);
    Check(state, "evidence codec round-trips a manifest",
          decode_status == knhv::TargetEvidenceCodecStatus::Success &&
              std::memcmp(&source, &decoded, sizeof(source)) == 0);

    std::array<knhv::u8, knhv::kTargetEvidenceWireEnvelopeSize - 1U> short_buffer{};
    written = 99U;
    Check(state, "evidence codec rejects a short output buffer",
          knhv::EncodeTargetEvidencePackage(
              &source, short_buffer.data(),
              static_cast<knhv::u32>(short_buffer.size()), &written) ==
                  knhv::TargetEvidenceCodecStatus::BufferTooSmall &&
              written == 0U);
}

void CheckTamperResistance(TestState& state) {
    const knhv::TargetEvidenceManifest source = MakeSyntheticManifest();
    std::array<knhv::u8, knhv::kTargetEvidenceWireEnvelopeSize> package{};
    knhv::u32 written = 0U;
    const auto encoded = knhv::EncodeTargetEvidencePackage(
        &source, package.data(), static_cast<knhv::u32>(package.size()),
        &written);
    Check(state, "evidence tamper fixture is created",
          encoded == knhv::TargetEvidenceCodecStatus::Success);
    if (encoded != knhv::TargetEvidenceCodecStatus::Success) return;

    auto tampered = package;
    tampered[sizeof(knhv::TargetEvidenceWireHeader) + 7U] ^= 0x5AU;
    knhv::TargetEvidenceManifest decoded{};
    Check(state, "evidence codec rejects payload tampering",
          knhv::DecodeTargetEvidencePackage(tampered.data(), written,
                                             &decoded) ==
              knhv::TargetEvidenceCodecStatus::DigestMismatch &&
              decoded.size == 0U);

    tampered = package;
    tampered[0] = static_cast<knhv::u8>('X');
    Check(state, "evidence codec rejects a bad magic before hashing",
          knhv::DecodeTargetEvidencePackage(tampered.data(), written,
                                             &decoded) ==
              knhv::TargetEvidenceCodecStatus::InvalidHeader);

    tampered = package;
    const std::size_t version_offset = sizeof(knhv::u8) * 8U;
    tampered[version_offset] = 0xFFU;
    Check(state, "evidence codec reports an unsupported wire version",
          knhv::DecodeTargetEvidencePackage(tampered.data(), written,
                                             &decoded) ==
              knhv::TargetEvidenceCodecStatus::UnsupportedVersion);

    Check(state, "evidence codec rejects trailing bytes",
          knhv::DecodeTargetEvidencePackage(
              package.data(), written - 1U, &decoded) ==
              knhv::TargetEvidenceCodecStatus::InvalidLength);
}

void CheckValidationAndSignature(TestState& state) {
    knhv::TargetEvidenceManifest invalid = MakeSyntheticManifest();
    invalid.artifact_count = 0U;
    std::array<knhv::u8, knhv::kTargetEvidenceWireEnvelopeSize> package{};
    knhv::u32 written = 0U;
    Check(state, "evidence codec validates the manifest before encoding",
          knhv::EncodeTargetEvidencePackage(
              &invalid, package.data(),
              static_cast<knhv::u32>(package.size()), &written) ==
              knhv::TargetEvidenceCodecStatus::InvalidManifest);

    const knhv::u8 content[] = {'K', 'N', 'H', 'V', 'E', 'V', '0', '1'};
    const knhv::u8 good_signature[] = {'o', 'k', '!'};
    const knhv::u8 bad_signature[] = {'n', 'o', '!'};
    Check(state, "signature adapter accepts a verified callback",
          knhv::VerifyTargetEvidenceDetachedSignature(
              content, sizeof(content), good_signature,
              sizeof(good_signature), MarkerVerifier, nullptr) ==
              knhv::TargetEvidenceCodecStatus::Success);
    Check(state, "signature adapter rejects a failed callback",
          knhv::VerifyTargetEvidenceDetachedSignature(
              content, sizeof(content), bad_signature,
              sizeof(bad_signature), MarkerVerifier, nullptr) ==
              knhv::TargetEvidenceCodecStatus::SignatureInvalid);
    Check(state, "signature adapter exposes unavailable verification",
          knhv::VerifyTargetEvidenceDetachedSignature(
              content, sizeof(content), good_signature,
              sizeof(good_signature), nullptr, nullptr) ==
              knhv::TargetEvidenceCodecStatus::SignatureUnavailable);
    Check(state, "codec status text is stable",
          std::string(knhv::TargetEvidenceCodecStatusText(
                          knhv::TargetEvidenceCodecStatus::DigestMismatch)) ==
              "digest-mismatch");
}

}  // namespace

void RunTargetEvidenceCodecContract(TestState& state) {
    CheckRoundTrip(state);
    CheckTamperResistance(state);
    CheckValidationAndSignature(state);
}

}  // namespace knhv_tests
