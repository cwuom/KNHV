#include <intrin.h>
#include <ntddk.h>
#include <wdmsec.h>

#include "knhv_control_device.h"
#include "knhv_logging.h"
#include "knhv_provider.h"

namespace knhv {
namespace {

constexpr ULONG kMaxIoctlBytes = 64U * 1024U;
constexpr u32 kTestSecurityPolicyVersion = 1U;
constexpr u64 kTestSecurityPolicyHash = 0x4B4E485654455354ULL;
constexpr GUID kControlDeviceClassGuid = {
    0x8b0f1d2a,
    0x7f4b,
    0x4a16,
    {0x9d, 0x35, 0x53, 0x90, 0x6c, 0x9f, 0xe4, 0x31}};
constexpr GUID kNestedDeviceClassGuid = {
    0x6e2a9f45,
    0x2d14,
    0x4fc7,
    {0xa1, 0x7e, 0x4e, 0x7d, 0x8b, 0x53, 0x0c, 0x92}};
constexpr ULONG kRemoveLockTag = 0x4B687652U;
constexpr u64 kSyntheticVmxonOperandLinear = 0U;
constexpr u64 kSyntheticVmcsOperandLinear = sizeof(u64);
constexpr u64 kSyntheticVmxonRegionGpa = kNestedPageSize;
constexpr u64 kSyntheticVmcsRegionGpa = 2ULL * kNestedPageSize;
constexpr u8 kKnownTestProviderGuid[16] = {
    0x4b, 0x4e, 0x48, 0x56, 0x2d, 0x4e, 0x54, 0x53,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01};

NTSTATUS SetIrpResult(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    if (irp == nullptr) return status;
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    return status;
}

NTSTATUS CompleteIrp(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    if (irp == nullptr) return status;
    SetIrpResult(irp, status, information);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

bool IsZeroWords(const u64* words, u32 count) {
    if (words == nullptr) return false;
    for (u32 index = 0; index < count; ++index) {
        if (words[index] != 0) return false;
    }
    return true;
}

bool VersionedInputFits(u32 version, u32 declared_size, u32 required_size,
                        ULONG supplied_length) {
    return supplied_length >= required_size &&
           declared_size >= required_size &&
           declared_size <= supplied_length &&
           IsVersionedBufferValid(version, declared_size, required_size);
}

bool VersionedV2InputFits(u32 version, u32 declared_size, u32 required_size,
                          ULONG supplied_length) {
    return supplied_length >= required_size &&
           declared_size >= required_size &&
           declared_size <= supplied_length &&
           IsAbiV2BufferValid(version, declared_size, required_size);
}

KnHvClientSession* FindSession(KnHvDeviceExtension* extension,
                               const HvSessionKey& key,
                               PFILE_OBJECT owner_file) {
    if (extension == nullptr || key.client_id == 0 || key.generation == 0 ||
        key.reserved != 0 || owner_file == nullptr) {
        return nullptr;
    }
    for (u32 index = 0; index < kMaxClientSessions; ++index) {
        KnHvClientSession* session = &extension->sessions[index];
        if (session->active != 0 &&
            session->owner_file == owner_file &&
            session->status.client_id == key.client_id &&
            session->status.generation == key.generation) {
            return session;
        }
    }
    return nullptr;
}

const KnHvClientSession* FindSession(const KnHvDeviceExtension* extension,
                                     const HvSessionKey& key,
                                     PFILE_OBJECT owner_file) {
    return FindSession(const_cast<KnHvDeviceExtension*>(extension), key,
                       owner_file);
}

bool GuestTranslate(void* context, u64 linear, u64* guest_physical,
                    u32 access);
bool GuestRead(void* context, u64 guest_physical, void* destination,
               u32 length);
bool GuestWrite(void* context, u64 guest_physical, const void* source,
                u32 length);

KnHvClientSession* AllocateSession(KnHvDeviceExtension* extension,
                                    PFILE_OBJECT owner_file) {
    if (extension == nullptr || owner_file == nullptr ||
        extension->active_sessions >= kMaxClientSessions) {
        return nullptr;
    }
    for (u32 index = 0; index < kMaxClientSessions; ++index) {
        KnHvClientSession* session = &extension->sessions[index];
        if (session->active == 0) {
            RtlZeroMemory(session, sizeof(*session));
            session->active = 1;
            session->owner_file = owner_file;
            ++extension->active_sessions;
            return session;
        }
    }
    return nullptr;
}

void InitializeNestedSession(KnHvClientSession* session) {
    if (session == nullptr) return;
    NestedMemory memory = {};
    memory.context = session;
    memory.translate = GuestTranslate;
    memory.read = GuestRead;
    memory.write = GuestWrite;
    NestedCapabilities capabilities = {};
    InitializeNestedCapabilities(&capabilities);
    InitializeNestedVcpu(&session->nested_vcpu, &capabilities, &memory);
    session->nested_vcpu.vmxe_enabled = 1U;
    const u32 revision = capabilities.vmx_revision;
    RtlCopyMemory(session->guest_memory + kSyntheticVmxonOperandLinear,
                  &kSyntheticVmxonRegionGpa, sizeof(kSyntheticVmxonRegionGpa));
    RtlCopyMemory(session->guest_memory + kSyntheticVmcsOperandLinear,
                  &kSyntheticVmcsRegionGpa, sizeof(kSyntheticVmcsRegionGpa));
    RtlCopyMemory(session->guest_memory + kSyntheticVmxonRegionGpa, &revision,
                  sizeof(revision));
    RtlCopyMemory(session->guest_memory + kSyntheticVmcsRegionGpa, &revision,
                  sizeof(revision));
    session->nested_ready = 1;
}

void ReleaseAllSessions(KnHvDeviceExtension* extension) {
    if (extension == nullptr) return;
    for (u32 index = 0; index < kMaxClientSessions; ++index) {
        KnHvClientSession* session = &extension->sessions[index];
        RtlZeroMemory(session, sizeof(*session));
    }
    extension->active_sessions = 0;
}

void ReleaseSessionsForFile(KnHvDeviceExtension* extension,
                            PFILE_OBJECT owner_file) {
    if (extension == nullptr || owner_file == nullptr) return;
    for (u32 index = 0; index < kMaxClientSessions; ++index) {
        KnHvClientSession* session = &extension->sessions[index];
        if (session->active != 0 && session->owner_file == owner_file) {
            RtlZeroMemory(session, sizeof(*session));
            if (extension->active_sessions != 0) --extension->active_sessions;
        }
    }
}

bool IsKnownTestProvider(const HvProviderRegistration& registration) {
    if (registration.security_policy_version !=
            kTestSecurityPolicyVersion ||
        registration.policy_hash != kTestSecurityPolicyHash ||
        registration.min_abi_version > kAbiVersion ||
        registration.max_abi_version < kAbiVersion) {
        return false;
    }
    for (u32 index = 0; index < sizeof(kKnownTestProviderGuid); ++index) {
        if (registration.provider_guid[index] != kKnownTestProviderGuid[index]) {
            return false;
        }
    }
    return true;
}

bool IsProviderKindValid(HvProviderKind kind) {
    switch (kind) {
        case HvProviderKind::BootL0Interposer:
        case HvProviderKind::CooperativeL1:
        case HvProviderKind::KnownLegacyAdapter:
        case HvProviderKind::LoadOnly:
        case HvProviderKind::ExternalL0Fallback:
        case HvProviderKind::WhpClient:
        case HvProviderKind::NativeExclusiveBaseline:
            return true;
        default:
            return false;
    }
}

bool DetectOuterL0() {
    int registers[4] = {};
    __cpuidex(registers, 1, 0);
    return (static_cast<u32>(registers[2]) & (1U << 31)) != 0;
}

bool GuestTranslate(void* context, u64 linear, u64* guest_physical,
                    u32 access) {
    if (context == nullptr || guest_physical == nullptr ||
        access == 0 || linear >= kNestedGuestMemoryBytes) {
        return false;
    }
    *guest_physical = linear;
    return true;
}

bool GuestRead(void* context, u64 guest_physical, void* destination,
               u32 length) {
    if (context == nullptr || destination == nullptr || length == 0 ||
        guest_physical >= kNestedGuestMemoryBytes ||
        length > kNestedGuestMemoryBytes - static_cast<u32>(guest_physical)) {
        return false;
    }
    KnHvClientSession* session = static_cast<KnHvClientSession*>(context);
    RtlCopyMemory(destination, session->guest_memory + guest_physical, length);
    return true;
}

bool GuestWrite(void* context, u64 guest_physical, const void* source,
                u32 length) {
    if (context == nullptr || source == nullptr || length == 0 ||
        guest_physical >= kNestedGuestMemoryBytes ||
        length > kNestedGuestMemoryBytes - static_cast<u32>(guest_physical)) {
        return false;
    }
    KnHvClientSession* session = static_cast<KnHvClientSession*>(context);
    RtlCopyMemory(session->guest_memory + guest_physical, source, length);
    return true;
}

HvProviderRequest MakeProviderRequest(
    const HvProviderRegistration& registration, bool identity_verified) {
    HvProviderRequest request = {};
    request.version = kAbiVersion;
    request.size = sizeof(request);
    request.identity_verified = identity_verified ? 1U : 0U;
    request.legacy_manifest_match =
        registration.kind == HvProviderKind::KnownLegacyAdapter ? 1U : 0U;
    request.requested_features = registration.advertised_features;
    switch (registration.kind) {
        case HvProviderKind::BootL0Interposer:
            request.mode = HvMode::BootL0Interposer;
            break;
        case HvProviderKind::CooperativeL1:
            request.mode = HvMode::CooperativeL1;
            break;
        case HvProviderKind::KnownLegacyAdapter:
            request.mode = HvMode::KnownLegacyCompat;
            request.legacy_manifest_match = 0;
            break;
        case HvProviderKind::LoadOnly:
            request.mode = HvMode::LoadOnly;
            break;
        case HvProviderKind::ExternalL0Fallback:
            request.mode = HvMode::ExternalL0Fallback;
            break;
        case HvProviderKind::WhpClient:
            request.mode = HvMode::WhpClient;
            break;
        case HvProviderKind::NativeExclusiveBaseline:
            request.mode = HvMode::NativeExclusiveBaseline;
            break;
        default:
            request.mode = static_cast<HvMode>(0);
            break;
    }
    return request;
}

bool RegistrationShapeValid(const HvProviderRegistration& registration) {
    const bool version_range_valid =
        registration.min_abi_version != 0 &&
        registration.min_abi_version <= registration.max_abi_version &&
        registration.min_abi_version <= kAbiVersion &&
        registration.max_abi_version >= kAbiMinVersion;
    const bool resource_limits_valid =
        registration.max_vcpus != 0 && registration.max_vcpus <= 256U &&
        registration.max_guest_pages != 0 &&
        registration.max_guest_pages <= (1U << 20);
    const bool feature_mask_valid =
        (registration.advertised_features & ~kKnownCapabilityMask) == 0;
    return IsVersionedBufferValid(registration.version, registration.size,
                                  sizeof(HvProviderRegistration)) &&
           version_range_valid && resource_limits_valid && feature_mask_valid &&
           IsProviderKindValid(registration.kind) &&
           IsZeroWords(registration.reserved, 2);
}

void FillSession(KnHvClientSession* session, u64 client_id, u32 generation,
                 HvStatus status, HvProviderKind provider,
                 bool synthetic_model) {
    if (session == nullptr) return;
    session->status = {};
    session->status.version = kAbiVersion;
    session->status.size = sizeof(session->status);
    session->status.client_id = client_id;
    session->status.generation = generation;
    session->status.load_success = 1;
    session->status.registration_ready =
        (status == HvStatus::Success || status == HvStatus::LoadOnly) ? 1U : 0U;
    session->status.virtualization_ready =
        status == HvStatus::Success && provider != HvProviderKind::LoadOnly &&
                !synthetic_model
            ? 1U
            : 0U;
    session->status.status = status;
    session->status.provider = provider;
}

NTSTATUS HandleQueryCaps(KnHvDeviceExtension* extension, PIRP irp,
                         ULONG input_length, ULONG output_length) {
    if (input_length < sizeof(HvQueryCapsIn) ||
        output_length < sizeof(HvQueryCapsOut)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvQueryCapsIn* input =
        static_cast<const HvQueryCapsIn*>(irp->AssociatedIrp.SystemBuffer);
    HvQueryCapsOut* output =
        static_cast<HvQueryCapsOut*>(irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedInputFits(input->version, input->size, sizeof(HvQueryCapsIn),
                            input_length)) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const u64 request_id = input->request_id;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    *output = {};
    output->version = kAbiVersion;
    output->size = sizeof(*output);
    output->request_id = request_id;
    output->status = HvStatus::Success;
    output->snapshot = extension->capabilities;
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleQueryCapsV2(KnHvDeviceExtension* extension, PIRP irp,
                           ULONG input_length, ULONG output_length) {
    if (input_length < sizeof(HvQueryCapsV2In) ||
        output_length < sizeof(HvQueryCapsV2Out)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvQueryCapsV2In* input =
        static_cast<const HvQueryCapsV2In*>(irp->AssociatedIrp.SystemBuffer);
    HvQueryCapsV2Out* output =
        static_cast<HvQueryCapsV2Out*>(irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedV2InputFits(input->version, input->size,
                              sizeof(HvQueryCapsV2In), input_length)) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const u64 request_id = input->request_id;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    *output = {};
    output->size = sizeof(*output);
    output->version = kAbiV2Version;
    output->request_id = request_id;
    output->status = HvStatus::Success;
    output->capabilities = MakeCapabilitySnapshotV2(&extension->capabilities);
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleAcquireLeaseV2(KnHvDeviceExtension* extension,
                              PFILE_OBJECT owner_file, PIRP irp,
                              ULONG input_length, ULONG output_length) {
    if (input_length < sizeof(HvAcquireLeaseV2In) ||
        output_length < sizeof(HvAcquireLeaseV2Out)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvAcquireLeaseV2In* input = static_cast<const HvAcquireLeaseV2In*>(
        irp->AssociatedIrp.SystemBuffer);
    HvAcquireLeaseV2Out* output = static_cast<HvAcquireLeaseV2Out*>(
        irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedV2InputFits(input->version, input->size,
                              sizeof(HvAcquireLeaseV2In), input_length) ||
        input->size < FIELD_OFFSET(HvAcquireLeaseV2In, request) +
                          sizeof(HvProviderRequestV2) ||
        input->request.size >
            input->size - FIELD_OFFSET(HvAcquireLeaseV2In, request) ||
        !VersionedV2InputFits(input->request.version, input->request.size,
                              sizeof(HvProviderRequestV2), input_length -
                                  FIELD_OFFSET(HvAcquireLeaseV2In, request))) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const HvProviderRequestV2 request = input->request;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    *output = {};
    output->size = sizeof(*output);
    output->version = kAbiV2Version;
    output->response.size = sizeof(output->response);
    output->response.version = kAbiV2Version;
    output->response.request_id = request.request_id;
    KnHvClientSession* session =
        FindSession(extension, request.session, owner_file);
    if (session == nullptr) {
        KeReleaseSpinLock(&extension->state_lock, old_irql);
        return SetIrpResult(irp, STATUS_INVALID_HANDLE, 0);
    }
    if (session->lease_active != 0) {
        output->response.status = HvStatus::Busy;
        KeReleaseSpinLock(&extension->state_lock, old_irql);
        return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
    }
    const HvCapabilitySnapshotV2 capabilities =
        MakeCapabilitySnapshotV2(&extension->capabilities);
    output->response.status = SelectProviderV2(
        &request, &capabilities, &output->response);
    if (output->response.status == HvStatus::Success &&
        request.mode == static_cast<u32>(HvLeaseModeV2::SyntheticLab) &&
        session->nested_ready == 0) {
        output->response.status = HvStatus::NestedUnavailable;
        output->response.provider = HvProviderKind::None;
        output->response.lease = {};
    }
    if (output->response.status == HvStatus::Success) {
        session->lease = output->response.lease;
        session->lease_active = 1U;
    } else {
        output->response.lease = {};
    }
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleReleaseLeaseV2(KnHvDeviceExtension* extension,
                              PFILE_OBJECT owner_file, PIRP irp,
                              ULONG input_length, ULONG output_length) {
    if (input_length < sizeof(HvReleaseLeaseV2In) ||
        output_length < sizeof(HvReleaseLeaseV2Out)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvReleaseLeaseV2In* input = static_cast<const HvReleaseLeaseV2In*>(
        irp->AssociatedIrp.SystemBuffer);
    HvReleaseLeaseV2Out* output = static_cast<HvReleaseLeaseV2Out*>(
        irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedV2InputFits(input->version, input->size,
                              sizeof(HvReleaseLeaseV2In), input_length) ||
        !IsOwnerLeaseV2Valid(&input->lease) ||
        input->lease.mode == static_cast<u32>(HvLeaseModeV2::None) ||
        input->session.reserved != 0) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    KnHvClientSession* session =
        FindSession(extension, input->session, owner_file);
    if (session == nullptr || session->lease_active == 0 ||
        session->lease.owner_id != input->lease.owner_id ||
        session->lease.generation != input->lease.generation ||
        session->lease.mode != input->lease.mode ||
        session->lease.flags != input->lease.flags) {
        KeReleaseSpinLock(&extension->state_lock, old_irql);
        return SetIrpResult(irp, STATUS_INVALID_HANDLE, 0);
    }
    RtlZeroMemory(&session->lease, sizeof(session->lease));
    session->lease_active = 0;
    *output = {};
    output->size = sizeof(*output);
    output->version = kAbiV2Version;
    output->request_id = input->request_id;
    output->status = HvStatus::Success;
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleRegisterClient(KnHvDeviceExtension* extension,
                              PFILE_OBJECT owner_file, PIRP irp,
                              ULONG input_length, ULONG output_length) {
    if (input_length < sizeof(HvRegisterClientIn) ||
        output_length < sizeof(HvRegisterClientOut)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvRegisterClientIn* input =
        static_cast<const HvRegisterClientIn*>(irp->AssociatedIrp.SystemBuffer);
    HvRegisterClientOut* output =
        static_cast<HvRegisterClientOut*>(irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedInputFits(input->version, input->size,
                            sizeof(HvRegisterClientIn), input_length) ||
        !RegistrationShapeValid(input->registration)) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const u64 request_id = input->request_id;
    const HvProviderRegistration registration = input->registration;
    HvRegisterClientOut response = {};
    response.version = kAbiVersion;
    response.size = sizeof(response);
    response.request_id = request_id;
    response.load_success = 1;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    const bool identity_verified =
        extension->nested_test_driver != 0 &&
        IsKnownTestProvider(registration);
    const HvProviderRequest request =
        MakeProviderRequest(registration, identity_verified);
    HvProviderKind selected = HvProviderKind::None;
    const HvStatus status = SelectProvider(&request, &extension->capabilities,
                                           &selected);
    response.status = status;
    response.provider = selected;
    if (status == HvStatus::Success || status == HvStatus::LoadOnly) {
        KnHvClientSession* session = AllocateSession(extension, owner_file);
        if (session == nullptr) {
            response.status = HvStatus::Busy;
            response.provider = HvProviderKind::None;
        } else {
            u64 client_id = ++extension->next_client;
            if (client_id == 0) client_id = ++extension->next_client;
            u32 generation = extension->capabilities.owner_generation ^
                             static_cast<u32>(client_id);
            if (generation == 0) generation = 1U;
            const bool synthetic_model =
                (extension->capabilities.status_flags &
                 kFlagSyntheticSnapshot) != 0;
            FillSession(session, client_id, generation, response.status,
                        response.provider, synthetic_model);
            if (extension->nested_test_driver != 0 &&
                response.status == HvStatus::Success) {
                InitializeNestedSession(session);
            }
            response.registration_ready = session->status.registration_ready;
            response.virtualization_ready =
                session->status.virtualization_ready;
            response.client_id = client_id;
            response.generation = generation;
        }
    }
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    *output = response;
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleQuerySession(KnHvDeviceExtension* extension,
                            PFILE_OBJECT owner_file, PIRP irp,
                            ULONG input_length, ULONG output_length) {
    if (input_length < sizeof(HvQuerySessionIn) ||
        output_length < sizeof(HvSessionStatusOut)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvQuerySessionIn* input =
        static_cast<const HvQuerySessionIn*>(irp->AssociatedIrp.SystemBuffer);
    HvSessionStatusOut* output =
        static_cast<HvSessionStatusOut*>(irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedInputFits(input->version, input->size,
                            sizeof(HvQuerySessionIn), input_length) ||
        input->session.reserved != 0) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const HvSessionKey key = input->session;
    HvSessionStatusOut response = {};
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    const KnHvClientSession* session =
        FindSession(extension, key, owner_file);
    const bool session_matches = session != nullptr;
    if (session_matches) response = session->status;
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    if (!session_matches) return SetIrpResult(irp, STATUS_INVALID_HANDLE, 0);
    *output = response;
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleReleaseSession(KnHvDeviceExtension* extension,
                              PFILE_OBJECT owner_file, PIRP irp,
                              ULONG input_length) {
    if (input_length < sizeof(HvQuerySessionIn)) {
        return SetIrpResult(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    const HvQuerySessionIn* input =
        static_cast<const HvQuerySessionIn*>(irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr ||
        !VersionedInputFits(input->version, input->size,
                            sizeof(HvQuerySessionIn), input_length) ||
        input->session.reserved != 0) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const HvSessionKey key = input->session;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    KnHvClientSession* session = FindSession(extension, key, owner_file);
    if (session == nullptr) {
        KeReleaseSpinLock(&extension->state_lock, old_irql);
        return SetIrpResult(irp, STATUS_INVALID_HANDLE, 0);
    }
    RtlZeroMemory(session, sizeof(*session));
    if (extension->active_sessions != 0) --extension->active_sessions;
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    return SetIrpResult(irp, STATUS_SUCCESS, 0);
}

NTSTATUS HandleNestedInstruction(KnHvDeviceExtension* extension,
                                 PFILE_OBJECT owner_file, PIRP irp,
                                 ULONG input_length, ULONG output_length) {
    if (extension->nested_test_driver == 0 ||
        input_length < sizeof(HvNestedInstructionIn) ||
        output_length < sizeof(HvNestedInstructionOut)) {
        return SetIrpResult(irp, STATUS_NOT_SUPPORTED, 0);
    }
    const HvNestedInstructionIn* input = static_cast<const HvNestedInstructionIn*>(
        irp->AssociatedIrp.SystemBuffer);
    HvNestedInstructionOut* output = static_cast<HvNestedInstructionOut*>(
        irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedInputFits(input->version, input->size,
                            sizeof(HvNestedInstructionIn), input_length) ||
        input->session.reserved != 0) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const u64 request_id = input->request_id;
    const HvSessionKey session_key = input->session;
    const VmxInstruction instruction = input->instruction;
    HvNestedInstructionOut response = {};
    response.version = kAbiVersion;
    response.size = sizeof(response);
    response.request_id = request_id;
    response.session = session_key;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    KnHvClientSession* session =
        FindSession(extension, session_key, owner_file);
    if (session == nullptr || session->nested_ready == 0) {
        KeReleaseSpinLock(&extension->state_lock, old_irql);
        return SetIrpResult(irp, STATUS_INVALID_HANDLE, 0);
    }
    response.result = DispatchNestedInstruction(&session->nested_vcpu,
                                                &instruction);
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    *output = response;
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

NTSTATUS HandleReflectExit(KnHvDeviceExtension* extension,
                           PFILE_OBJECT owner_file, PIRP irp,
                           ULONG input_length, ULONG output_length) {
    if (extension->nested_test_driver == 0 ||
        input_length < sizeof(HvNestedExitIn) ||
        output_length < sizeof(HvNestedExitOut)) {
        return SetIrpResult(irp, STATUS_NOT_SUPPORTED, 0);
    }
    const HvNestedExitIn* input =
        static_cast<const HvNestedExitIn*>(irp->AssociatedIrp.SystemBuffer);
    HvNestedExitOut* output =
        static_cast<HvNestedExitOut*>(irp->AssociatedIrp.SystemBuffer);
    if (input == nullptr || output == nullptr ||
        !VersionedInputFits(input->version, input->size,
                            sizeof(HvNestedExitIn), input_length) ||
        input->session.reserved != 0) {
        return SetIrpResult(irp, STATUS_INVALID_PARAMETER, 0);
    }
    const u64 request_id = input->request_id;
    const HvSessionKey session_key = input->session;
    const NestedExitRecord exit_record = input->exit_record;
    HvNestedExitOut response = {};
    response.version = kAbiVersion;
    response.size = sizeof(response);
    response.request_id = request_id;
    response.session = session_key;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    KnHvClientSession* session =
        FindSession(extension, session_key, owner_file);
    if (session == nullptr || session->nested_ready == 0) {
        KeReleaseSpinLock(&extension->state_lock, old_irql);
        return SetIrpResult(irp, STATUS_INVALID_HANDLE, 0);
    }
    response.result = ReflectNestedExit(&session->nested_vcpu, &exit_record);
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    *output = response;
    return SetIrpResult(irp, STATUS_SUCCESS, sizeof(*output));
}

}  // namespace

extern "C" NTSTATUS KnHvInitializeControlDriver(
    PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path,
    BOOLEAN nested_test_driver) {
    UNREFERENCED_PARAMETER(registry_path);
    if (driver_object == nullptr) return STATUS_INVALID_PARAMETER;

    const wchar_t* device_name_text = nested_test_driver
                                          ? KNHV_NESTED_DEVICE_NAME
                                          : KNHV_CONTROL_DEVICE_NAME;
    const wchar_t* dos_name_text = nested_test_driver ? KNHV_NESTED_DOS_NAME
                                                      : KNHV_CONTROL_DOS_NAME;
    UNICODE_STRING device_name = {};
    UNICODE_STRING dos_name = {};
    RtlInitUnicodeString(&device_name, device_name_text);
    RtlInitUnicodeString(&dos_name, dos_name_text);
    PDEVICE_OBJECT device = nullptr;
    const GUID* class_guid = nested_test_driver ? &kNestedDeviceClassGuid
                                                : &kControlDeviceClassGuid;
    const UNICODE_STRING* sddl = &SDDL_DEVOBJ_SYS_ALL_ADM_ALL;
    NTSTATUS status = IoCreateDeviceSecure(
        driver_object, sizeof(KnHvDeviceExtension), &device_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, sddl, class_guid,
        &device);
    if (!NT_SUCCESS(status)) return status;

    KnHvDeviceExtension* extension =
        static_cast<KnHvDeviceExtension*>(device->DeviceExtension);
    RtlZeroMemory(extension, sizeof(*extension));
    KeInitializeSpinLock(&extension->state_lock);
    IoInitializeRemoveLock(&extension->remove_lock, kRemoveLockTag, 0, 0);
    extension->device = device;
    extension->nested_test_driver = nested_test_driver ? 1U : 0U;
    extension->initialized = 1U;
    extension->dos_name = dos_name;
    extension->capabilities =
        // WHP is a user-mode API and is not probed from this kernel image
        MakeFallbackCapabilitySnapshot(DetectOuterL0(), FALSE);
    extension->capabilities.owner_generation = 1U;
    extension->capabilities.boot_generation = 1U;
    if (nested_test_driver != FALSE) {
        extension->capabilities.feature_bits |=
            kCapEpt | kCapVpid | kCapNestedVmx | kCapVirtualTlbFlush;
        extension->capabilities.status_flags |=
            kFlagNestedVmx | kFlagSyntheticSnapshot;
        extension->capabilities.e_vmcs_version = 0U;
    }

    device->Flags |= DO_BUFFERED_IO;
    for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        driver_object->MajorFunction[index] = KnHvDispatchUnsupported;
    }
    driver_object->MajorFunction[IRP_MJ_CREATE] = KnHvDispatchCreate;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = KnHvDispatchClose;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        KnHvDispatchDeviceControl;
    driver_object->DriverUnload = KnHvUnloadControlDriver;
    status = IoCreateSymbolicLink(&dos_name, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    KNHV_PASSIVE_PRINT("[KNHV] control device ready: nested=%u\n",
                       nested_test_driver != FALSE ? 1U : 0U);
    return STATUS_SUCCESS;
}

extern "C" void KnHvUnloadControlDriver(PDRIVER_OBJECT driver_object) {
    if (driver_object == nullptr) return;
    PDEVICE_OBJECT device = driver_object->DeviceObject;
    if (device == nullptr) return;
    KnHvDeviceExtension* extension =
        static_cast<KnHvDeviceExtension*>(device->DeviceExtension);
    if (extension != nullptr) {
        const NTSTATUS lock_status =
            IoAcquireRemoveLock(&extension->remove_lock, driver_object);
        if (NT_SUCCESS(lock_status)) {
            IoReleaseRemoveLockAndWait(&extension->remove_lock, driver_object);
        }
        extension->initialized = 0;
        ReleaseAllSessions(extension);
    }
    if (extension != nullptr && extension->dos_name.Buffer != nullptr) {
        IoDeleteSymbolicLink(&extension->dos_name);
    }
    IoDeleteDevice(device);
}

extern "C" NTSTATUS KnHvDispatchCreate(PDEVICE_OBJECT device_object,
                                         PIRP irp) {
    if (device_object == nullptr || irp == nullptr) {
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    KnHvDeviceExtension* extension =
        static_cast<KnHvDeviceExtension*>(device_object->DeviceExtension);
    if (extension == nullptr || extension->initialized == 0) {
        return CompleteIrp(irp, STATUS_INVALID_DEVICE_STATE, 0);
    }
    const NTSTATUS lock_status =
        IoAcquireRemoveLock(&extension->remove_lock, irp);
    if (!NT_SUCCESS(lock_status)) return CompleteIrp(irp, lock_status, 0);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (stack == nullptr || stack->FileObject == nullptr) {
        IoReleaseRemoveLock(&extension->remove_lock, irp);
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    stack->FileObject->FsContext = stack->FileObject;
    const NTSTATUS result = SetIrpResult(irp, STATUS_SUCCESS, 0);
    IoReleaseRemoveLock(&extension->remove_lock, irp);
    return CompleteIrp(irp, result, 0);
}

extern "C" NTSTATUS KnHvDispatchClose(PDEVICE_OBJECT device_object,
                                       PIRP irp) {
    if (device_object == nullptr || irp == nullptr) {
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    KnHvDeviceExtension* extension =
        static_cast<KnHvDeviceExtension*>(device_object->DeviceExtension);
    if (extension == nullptr || extension->initialized == 0) {
        return CompleteIrp(irp, STATUS_INVALID_DEVICE_STATE, 0);
    }
    const NTSTATUS lock_status =
        IoAcquireRemoveLock(&extension->remove_lock, irp);
    if (!NT_SUCCESS(lock_status)) return CompleteIrp(irp, lock_status, 0);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (stack == nullptr || stack->FileObject == nullptr) {
        IoReleaseRemoveLock(&extension->remove_lock, irp);
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&extension->state_lock, &old_irql);
    ReleaseSessionsForFile(extension, stack->FileObject);
    KeReleaseSpinLock(&extension->state_lock, old_irql);
    stack->FileObject->FsContext = nullptr;
    const NTSTATUS result = SetIrpResult(irp, STATUS_SUCCESS, 0);
    IoReleaseRemoveLock(&extension->remove_lock, irp);
    return CompleteIrp(irp, result, 0);
}

extern "C" NTSTATUS KnHvDispatchUnsupported(PDEVICE_OBJECT device_object,
                                              PIRP irp) {
    if (device_object == nullptr || irp == nullptr) {
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    KnHvDeviceExtension* extension =
        static_cast<KnHvDeviceExtension*>(device_object->DeviceExtension);
    if (extension == nullptr || extension->initialized == 0) {
        return CompleteIrp(irp, STATUS_INVALID_DEVICE_STATE, 0);
    }
    const NTSTATUS lock_status =
        IoAcquireRemoveLock(&extension->remove_lock, irp);
    if (!NT_SUCCESS(lock_status)) return CompleteIrp(irp, lock_status, 0);
    const NTSTATUS result =
        SetIrpResult(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    IoReleaseRemoveLock(&extension->remove_lock, irp);
    return CompleteIrp(irp, result, 0);
}

extern "C" NTSTATUS KnHvDispatchDeviceControl(PDEVICE_OBJECT device_object,
                                               PIRP irp) {
    if (device_object == nullptr || irp == nullptr ||
        irp->AssociatedIrp.SystemBuffer == nullptr) {
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    KnHvDeviceExtension* extension =
        static_cast<KnHvDeviceExtension*>(device_object->DeviceExtension);
    if (extension == nullptr || extension->initialized == 0) {
        return CompleteIrp(irp, STATUS_INVALID_DEVICE_STATE, 0);
    }
    const PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (stack == nullptr || stack->FileObject == nullptr) {
        return CompleteIrp(irp, STATUS_INVALID_PARAMETER, 0);
    }
    PFILE_OBJECT owner_file = stack->FileObject;
    if (owner_file->FsContext != owner_file) {
        return CompleteIrp(irp, STATUS_INVALID_HANDLE, 0);
    }
    const NTSTATUS lock_status =
        IoAcquireRemoveLock(&extension->remove_lock, irp);
    if (!NT_SUCCESS(lock_status)) return CompleteIrp(irp, lock_status, 0);
    const ULONG input_length = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG output_length =
        stack->Parameters.DeviceIoControl.OutputBufferLength;
    if (input_length > kMaxIoctlBytes || output_length > kMaxIoctlBytes) {
        IoReleaseRemoveLock(&extension->remove_lock, irp);
        return CompleteIrp(irp, STATUS_INVALID_BUFFER_SIZE, 0);
    }
    NTSTATUS result = STATUS_INVALID_DEVICE_REQUEST;
    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_KNHV_QUERY_CAPS:
            result = HandleQueryCaps(extension, irp, input_length, output_length);
            break;
        case IOCTL_KNHV_QUERY_CAPS_V2:
            result = HandleQueryCapsV2(extension, irp, input_length,
                                        output_length);
            break;
        case IOCTL_KNHV_REGISTER_CLIENT:
            result = HandleRegisterClient(extension, owner_file, irp,
                                          input_length, output_length);
            break;
        case IOCTL_KNHV_QUERY_SESSION:
            result = HandleQuerySession(extension, owner_file, irp,
                                        input_length, output_length);
            break;
        case IOCTL_KNHV_RELEASE_SESSION:
            result = HandleReleaseSession(extension, owner_file, irp,
                                          input_length);
            break;
        case IOCTL_KNHV_ACQUIRE_LEASE_V2:
            result = HandleAcquireLeaseV2(extension, owner_file, irp,
                                          input_length, output_length);
            break;
        case IOCTL_KNHV_RELEASE_LEASE_V2:
            result = HandleReleaseLeaseV2(extension, owner_file, irp,
                                          input_length, output_length);
            break;
        case IOCTL_KNHV_NESTED_INSTRUCTION:
            result = HandleNestedInstruction(extension, owner_file, irp,
                                             input_length, output_length);
            break;
        case IOCTL_KNHV_REFLECT_EXIT:
            result = HandleReflectExit(extension, owner_file, irp, input_length,
                                       output_length);
            break;
        default:
            result = SetIrpResult(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            break;
    }
    const ULONG_PTR information = irp->IoStatus.Information;
    IoReleaseRemoveLock(&extension->remove_lock, irp);
    return CompleteIrp(irp, result, information);
}

}  // namespace knhv
