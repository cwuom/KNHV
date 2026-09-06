#include "test_support.h"

#include "knhv_vmcs_shadow.h"
#include "knhv_nested.h"

namespace knhv_tests {
namespace {

knhv::VmcsShadowCapabilities MakeCapabilities(std::uint64_t generation = 10) {
    knhv::VmcsShadowCapabilities capabilities = {};
    capabilities.size = sizeof(capabilities);
    capabilities.version = knhv::kVmcsShadowContractVersion;
    capabilities.feature_flags = knhv::kVmcsShadowCapSupported |
                                 knhv::kVmcsShadowCapLinkPointer |
                                 knhv::kVmcsShadowCapReadBitmap |
                                 knhv::kVmcsShadowCapWriteBitmap;
    capabilities.max_fields = 64;
    capabilities.physical_address_bits = 48;
    capabilities.generation = generation;
    return capabilities;
}

knhv::VmcsShadowConfig MakeConfig(std::uint64_t generation = 10) {
    knhv::VmcsShadowConfig config = {};
    config.size = sizeof(config);
    config.version = knhv::kVmcsShadowContractVersion;
    config.link_pointer = 0x1000;
    config.read_bitmap_physical = 0x2000;
    config.write_bitmap_physical = 0x3000;
    config.flags = knhv::kVmcsShadowEnableLinkPointer |
                  knhv::kVmcsShadowEnableReadBitmap |
                  knhv::kVmcsShadowEnableWriteBitmap;
    config.generation = generation;
    return config;
}

knhv::VmcsShadowAccess MakeAccess(std::uint32_t index, std::uint32_t encoding,
                                  knhv::VmcsShadowAccessOperation operation,
                                  std::uint64_t generation = 10) {
    knhv::VmcsShadowAccess access = {};
    access.size = sizeof(access);
    access.version = knhv::kVmcsShadowContractVersion;
    access.field_index = index;
    access.encoding = encoding;
    access.operation = static_cast<std::uint32_t>(operation);
    access.generation = generation;
    return access;
}

void CheckVmcsShadowValidation(TestState& state) {
    const auto capabilities = MakeCapabilities();
    auto config = MakeConfig();
    Check(state, "VMCS shadow capabilities require the supported bit",
          knhv::IsVmcsShadowCapabilitiesValid(&capabilities));
    Check(state, "VMCS shadow config validates link and bitmap pages",
          knhv::IsVmcsShadowConfigValid(
              &config, capabilities.physical_address_bits,
              capabilities.max_fields));
    config.flags &= ~knhv::kVmcsShadowEnableReadBitmap;
    config.read_bitmap_physical = knhv::kVmcsShadowNoLinkPointer;
    Check(state, "disabled VMCS shadow bitmap has no physical page",
          knhv::IsVmcsShadowConfigValid(
              &config, capabilities.physical_address_bits,
              capabilities.max_fields));
    config.flags |= knhv::kVmcsShadowEnableReadBitmap;
    config.read_bitmap_physical = 0x2000;
    config.read_bitmap[64 / 8] |= 1U << (64 % 8);
    Check(state, "VMCS shadow config rejects bits beyond the field limit",
          !knhv::IsVmcsShadowConfigValid(
              &config, capabilities.physical_address_bits,
              capabilities.max_fields));
    auto invalid_caps = capabilities;
    invalid_caps.feature_flags |= 1ULL << 20;
    Check(state, "VMCS shadow capabilities reject unknown feature bits",
          !knhv::IsVmcsShadowCapabilitiesValid(&invalid_caps));
}

void CheckVmcsShadowAccess(TestState& state) {
    const auto capabilities = MakeCapabilities();
    const auto config = MakeConfig();
    knhv::VmcsShadowImage image = {};
    Check(state, "VMCS shadow starts in the active state",
          knhv::BeginVmcsShadow(&capabilities, &config, &image) &&
              image.state == static_cast<std::uint32_t>(
                  knhv::VmcsShadowState::Active));

    auto read = MakeAccess(
        20, knhv::kVmcsFieldGuestRip,
        knhv::VmcsShadowAccessOperation::Read);
    image.fields[20] = 0x123456789ULL;
    knhv::VmcsShadowDecision decision = {};
    Check(state, "VMREAD uses the shadow image when bitmap allows it",
          knhv::ApplyVmcsShadowAccess(&capabilities, &config, &image, &read,
                                      10, &decision) ==
                  knhv::VmcsShadowAccessResult::Shadow &&
              decision.value == image.fields[20]);

    auto write = MakeAccess(
        20, knhv::kVmcsFieldGuestRip,
        knhv::VmcsShadowAccessOperation::Write);
    write.value = 0xFEDCBA987ULL;
    Check(state, "VMWRITE updates the shadow image and dirty bit",
          knhv::ApplyVmcsShadowAccess(&capabilities, &config, &image, &write,
                                      10, &decision) ==
                  knhv::VmcsShadowAccessResult::Shadow &&
              image.fields[20] == write.value &&
              (image.dirty_bitmap[0] & (1ULL << 20)) != 0);

    auto read_intercept = read;
    auto intercepted_config = config;
    intercepted_config.read_bitmap[20 / 8] |= 1U << (20 % 8);
    Check(state, "VMREAD bitmap forces reflection to L0",
          knhv::ClassifyVmcsShadowAccess(
              &capabilities, &intercepted_config, &image, &read_intercept,
              10, &decision) == knhv::VmcsShadowAccessResult::ReflectExit);

    auto read_only_write = MakeAccess(
        14, knhv::kVmcsFieldExitReason,
        knhv::VmcsShadowAccessOperation::Write);
    Check(state, "VMWRITE to a read-only field is reflected",
          knhv::ClassifyVmcsShadowAccess(
              &capabilities, &config, &image, &read_only_write, 10,
              &decision) == knhv::VmcsShadowAccessResult::ReflectExit);

    auto stale = read;
    stale.generation = 9;
    Check(state, "VMCS shadow access rejects a stale generation",
          knhv::ClassifyVmcsShadowAccess(&capabilities, &config, &image,
                                         &stale, 10, &decision) ==
              knhv::VmcsShadowAccessResult::Stale);
    auto unknown = read;
    unknown.encoding = 0xDEAD;
    Check(state, "VMCS shadow access rejects an unknown field encoding",
          !knhv::IsVmcsShadowAccessValid(&unknown));
}

void CheckVmcsShadowLifecycle(TestState& state) {
    auto capabilities = MakeCapabilities();
    auto config = MakeConfig();
    knhv::VmcsShadowImage image = {};
    Check(state, "VMCS shadow can be cleared before CPU migration",
          knhv::BeginVmcsShadow(&capabilities, &config, &image) &&
              knhv::ClearVmcsShadow(&image, 10) &&
              image.state == static_cast<std::uint32_t>(
                  knhv::VmcsShadowState::Cleared));
    capabilities.generation = 11;
    config.generation = 11;
    Check(state, "VMCS shadow rebind requires a newer generation",
          knhv::RebindVmcsShadow(&capabilities, &config, 11, &image) &&
              image.generation == 11 &&
              image.state == static_cast<std::uint32_t>(
                  knhv::VmcsShadowState::Active));
    Check(state, "VMCS shadow quarantine blocks further access",
          knhv::QuarantineVmcsShadow(&image, 11) &&
              image.state == static_cast<std::uint32_t>(
                  knhv::VmcsShadowState::Quarantined));
    auto access = MakeAccess(
        20, knhv::kVmcsFieldGuestRip,
        knhv::VmcsShadowAccessOperation::Read, 11);
    knhv::VmcsShadowDecision decision = {};
    Check(state, "quarantined VMCS shadow returns a quarantine result",
          knhv::ClassifyVmcsShadowAccess(&capabilities, &config, &image,
                                         &access, 11, &decision) ==
              knhv::VmcsShadowAccessResult::Quarantined);
    auto unsupported = MakeCapabilities();
    unsupported.feature_flags = knhv::kVmcsShadowCapSupported;
    auto unsupported_config = MakeConfig();
    Check(state, "VMCS shadow rejects an unavailable bitmap capability",
          !knhv::BeginVmcsShadow(&unsupported, &unsupported_config, &image));
}

}  // namespace

void RunVmcsShadowModelContract(TestState& state) {
    CheckVmcsShadowValidation(state);
    CheckVmcsShadowAccess(state);
    CheckVmcsShadowLifecycle(state);
}

}  // namespace knhv_tests
