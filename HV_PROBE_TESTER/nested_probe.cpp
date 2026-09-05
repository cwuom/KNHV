#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>

#include "knhv_control_ioctl.h"

namespace {

constexpr wchar_t kDefaultDeviceName[] = L"\\\\.\\KNHVNestedTest";
constexpr knhv::u64 kRequestedFeatures =
    knhv::kCapEpt | knhv::kCapVpid | knhv::kCapNestedVmx |
    knhv::kCapVirtualTlbFlush;
constexpr knhv::u64 kTestPolicyHash = 0x4B4E485654455354ULL;
constexpr knhv::u32 kTestPolicyVersion = 1U;
constexpr knhv::u8 kTestProviderGuid[16] = {
    0x4b, 0x4e, 0x48, 0x56, 0x2d, 0x4e, 0x54, 0x53,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
};
constexpr knhv::u64 kVmxonOperandLinear = 0U;
constexpr knhv::u64 kVmcsOperandLinear = sizeof(knhv::u64);
constexpr knhv::u64 kPrimaryActivateSecondary = 1ULL << 31;

struct ProbeState {
    unsigned passed = 0;
    unsigned failed = 0;
};

struct VmcsWrite {
    const char* name;
    knhv::u32 encoding;
    knhv::u64 value;
};

void Check(ProbeState* state, const char* name, bool condition) {
    if (state == nullptr) return;
    if (condition) {
        ++state->passed;
        std::printf("PASS  %s\n", name);
        return;
    }
    ++state->failed;
    std::printf("FAIL  %s\n", name);
}

void PrintWin32Failure(const char* operation) {
    std::printf("FAIL  %s: Win32 error=%lu\n", operation,
                static_cast<unsigned long>(GetLastError()));
}

bool QueryCaps(HANDLE device, knhv::u64 request_id,
               knhv::HvQueryCapsOut* response) {
    if (response == nullptr) return false;
    knhv::HvQueryCapsIn request = {};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = request_id;
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_QUERY_CAPS, &request,
                        static_cast<DWORD>(sizeof(request)), response,
                        static_cast<DWORD>(sizeof(*response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_QUERY_CAPS");
        return false;
    }
    return returned == sizeof(*response) &&
           response->version == knhv::kAbiVersion &&
           response->size == sizeof(*response) &&
           response->request_id == request_id;
}

bool QueryCapsV2(HANDLE device, knhv::u64 request_id,
                 knhv::HvQueryCapsV2Out* response) {
    if (response == nullptr) return false;
    knhv::HvQueryCapsV2In request = {};
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.version = knhv::kAbiV2Version;
    request.request_id = request_id;
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_QUERY_CAPS_V2, &request,
                        static_cast<DWORD>(sizeof(request)), response,
                        static_cast<DWORD>(sizeof(*response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_QUERY_CAPS_V2");
        return false;
    }
    return returned == sizeof(*response) &&
           response->version == knhv::kAbiV2Version &&
           response->size == sizeof(*response) &&
           response->request_id == request_id;
}

bool RegisterClient(HANDLE device, knhv::u64 request_id,
                    knhv::HvRegisterClientOut* response) {
    if (response == nullptr) return false;
    knhv::HvRegisterClientIn request = {};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = request_id;
    request.registration.version = knhv::kAbiVersion;
    request.registration.size =
        static_cast<knhv::u32>(sizeof(request.registration));
    std::memcpy(request.registration.provider_guid, kTestProviderGuid,
                sizeof(kTestProviderGuid));
    request.registration.min_abi_version = knhv::kAbiVersion;
    request.registration.max_abi_version = knhv::kAbiVersion;
    request.registration.kind = knhv::HvProviderKind::CooperativeL1;
    request.registration.security_policy_version = kTestPolicyVersion;
    request.registration.advertised_features = kRequestedFeatures;
    request.registration.max_vcpus = 1U;
    request.registration.max_guest_pages = 16U;
    request.registration.policy_hash = kTestPolicyHash;
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_REGISTER_CLIENT, &request,
                        static_cast<DWORD>(sizeof(request)), response,
                        static_cast<DWORD>(sizeof(*response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_REGISTER_CLIENT");
        return false;
    }
    return returned == sizeof(*response) &&
           response->version == knhv::kAbiVersion &&
           response->size == sizeof(*response) &&
           response->request_id == request_id;
}

bool QuerySession(HANDLE device, knhv::u64 request_id,
                  const knhv::HvSessionKey& session,
                  knhv::HvSessionStatusOut* response) {
    if (response == nullptr) return false;
    knhv::HvQuerySessionIn request = {};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = request_id;
    request.session = session;
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_QUERY_SESSION, &request,
                        static_cast<DWORD>(sizeof(request)), response,
                        static_cast<DWORD>(sizeof(*response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_QUERY_SESSION");
        return false;
    }
    return returned == sizeof(*response) &&
           response->version == knhv::kAbiVersion &&
           response->size == sizeof(*response);
}

bool ReleaseSession(HANDLE device, knhv::u64 request_id,
                    const knhv::HvSessionKey& session) {
    knhv::HvQuerySessionIn request = {};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = request_id;
    request.session = session;
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_RELEASE_SESSION, &request,
                        static_cast<DWORD>(sizeof(request)), nullptr, 0,
                        &returned, nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_RELEASE_SESSION");
        return false;
    }
    return returned == 0;
}

bool AcquireSyntheticLease(HANDLE device, knhv::u64 request_id,
                           const knhv::HvSessionKey& session,
                           knhv::HvAcquireLeaseV2Out* response) {
    if (response == nullptr) return false;
    knhv::HvAcquireLeaseV2In request = {};
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.version = knhv::kAbiV2Version;
    request.request.size = static_cast<knhv::u32>(sizeof(request.request));
    request.request.version = knhv::kAbiV2Version;
    request.request.request_id = request_id;
    request.request.session = session;
    request.request.required_provider_features = knhv::kCapNestedVmx;
    request.request.mode = static_cast<knhv::u32>(
        knhv::HvLeaseModeV2::SyntheticLab);
    request.request.flags = knhv::kRequestFlagReadOnly;
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_ACQUIRE_LEASE_V2, &request,
                        static_cast<DWORD>(sizeof(request)), response,
                        static_cast<DWORD>(sizeof(*response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_ACQUIRE_LEASE_V2");
        return false;
    }
    return returned == sizeof(*response) &&
           response->version == knhv::kAbiV2Version &&
           response->size == sizeof(*response) &&
           response->response.version == knhv::kAbiV2Version &&
           response->response.size == sizeof(response->response) &&
           response->response.request_id == request_id;
}

bool ReleaseLeaseV2(HANDLE device, knhv::u64 request_id,
                    const knhv::HvSessionKey& session,
                    const knhv::HvOwnerLeaseV2& lease) {
    knhv::HvReleaseLeaseV2In request = {};
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.version = knhv::kAbiV2Version;
    request.request_id = request_id;
    request.session = session;
    request.lease = lease;
    knhv::HvReleaseLeaseV2Out response = {};
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_RELEASE_LEASE_V2, &request,
                        static_cast<DWORD>(sizeof(request)), &response,
                        static_cast<DWORD>(sizeof(response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_RELEASE_LEASE_V2");
        return false;
    }
    return returned == sizeof(response) &&
           response.version == knhv::kAbiV2Version &&
           response.size == sizeof(response) &&
           response.request_id == request_id &&
           response.status == knhv::HvStatus::Success;
}

knhv::VmxInstruction MakeInstruction(knhv::VmxOpcode opcode) {
    knhv::VmxInstruction instruction = {};
    instruction.version = knhv::kNestedModelVersion;
    instruction.size = static_cast<knhv::u32>(sizeof(instruction));
    instruction.opcode = opcode;
    instruction.instruction_length = 3U;
    return instruction;
}

bool SendInstruction(HANDLE device, knhv::u64 request_id,
                     const knhv::HvSessionKey& session,
                     const knhv::VmxInstruction& instruction,
                     knhv::NestedResult* result) {
    if (result == nullptr) return false;
    knhv::HvNestedInstructionIn request = {};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = request_id;
    request.session = session;
    request.instruction = instruction;
    knhv::HvNestedInstructionOut response = {};
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_NESTED_INSTRUCTION, &request,
                        static_cast<DWORD>(sizeof(request)), &response,
                        static_cast<DWORD>(sizeof(response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_NESTED_INSTRUCTION");
        return false;
    }
    if (returned != sizeof(response) || response.version != knhv::kAbiVersion ||
        response.size != sizeof(response) || response.request_id != request_id ||
        response.session.client_id != session.client_id ||
        response.session.generation != session.generation ||
        response.session.reserved != 0) {
        std::puts("FAIL  malformed nested instruction response");
        return false;
    }
    *result = response.result;
    return true;
}

bool ReflectExit(HANDLE device, knhv::u64 request_id,
                 const knhv::HvSessionKey& session,
                 const knhv::NestedExitRecord& exit_record,
                 knhv::NestedResult* result) {
    if (result == nullptr) return false;
    knhv::HvNestedExitIn request = {};
    request.version = knhv::kAbiVersion;
    request.size = static_cast<knhv::u32>(sizeof(request));
    request.request_id = request_id;
    request.session = session;
    request.exit_record = exit_record;
    knhv::HvNestedExitOut response = {};
    DWORD returned = 0;
    if (DeviceIoControl(device, IOCTL_KNHV_REFLECT_EXIT, &request,
                        static_cast<DWORD>(sizeof(request)), &response,
                        static_cast<DWORD>(sizeof(response)), &returned,
                        nullptr) == FALSE) {
        PrintWin32Failure("IOCTL_KNHV_REFLECT_EXIT");
        return false;
    }
    if (returned != sizeof(response) || response.version != knhv::kAbiVersion ||
        response.size != sizeof(response) || response.request_id != request_id ||
        response.session.client_id != session.client_id ||
        response.session.generation != session.generation ||
        response.session.reserved != 0) {
        std::puts("FAIL  malformed nested exit response");
        return false;
    }
    *result = response.result;
    return true;
}

bool ExpectResult(ProbeState* state, const char* name,
                  const knhv::NestedResult& result,
                  knhv::HvStatus status, knhv::NestedAction action) {
    const bool matches = result.status == status && result.action == action;
    std::printf("%s  %s status=%u action=%u error=%u flags=0x%llX value=0x%llX\n",
                matches ? "PASS" : "FAIL", name,
                static_cast<unsigned>(result.status),
                static_cast<unsigned>(result.action), result.instruction_error,
                static_cast<unsigned long long>(result.rflags),
                static_cast<unsigned long long>(result.value));
    if (state != nullptr) {
        if (matches) {
            ++state->passed;
        } else {
            ++state->failed;
        }
    }
    return matches;
}

bool WriteVmcsField(HANDLE device, knhv::u64* request_id,
                    const knhv::HvSessionKey& session,
                    const VmcsWrite& write, ProbeState* state) {
    if (request_id == nullptr) return false;
    knhv::VmxInstruction instruction = MakeInstruction(knhv::VmxOpcode::Vmwrite);
    instruction.encoding = write.encoding;
    instruction.source = write.value;
    knhv::NestedResult result = {};
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result)) {
        return false;
    }
    return ExpectResult(state, write.name, result, knhv::HvStatus::Success,
                        knhv::NestedAction::ResumeL1);
}

bool RunNestedSequence(HANDLE device, knhv::u64* request_id,
                       const knhv::HvSessionKey& session, ProbeState* state) {
    if (request_id == nullptr) return false;
    knhv::NestedResult result = {};
    knhv::VmxInstruction instruction = MakeInstruction(knhv::VmxOpcode::Vmxon);
    instruction.linear_operand = kVmxonOperandLinear;
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMXON", result, knhv::HvStatus::Success,
                      knhv::NestedAction::ResumeL1)) {
        return false;
    }

    instruction = MakeInstruction(knhv::VmxOpcode::Vmclear);
    instruction.linear_operand = kVmcsOperandLinear;
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMCLEAR", result, knhv::HvStatus::Success,
                      knhv::NestedAction::ResumeL1)) {
        return false;
    }

    instruction = MakeInstruction(knhv::VmxOpcode::Vmptrld);
    instruction.linear_operand = kVmcsOperandLinear;
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMPTRLD", result, knhv::HvStatus::Success,
                      knhv::NestedAction::ResumeL1)) {
        return false;
    }

    const VmcsWrite entry_state[] = {
        {"VMWRITE pin controls", knhv::kVmcsFieldPinControls, 0U},
        {"VMWRITE primary controls", knhv::kVmcsFieldPrimaryControls,
         kPrimaryActivateSecondary},
        {"VMWRITE secondary controls", knhv::kVmcsFieldSecondaryControls,
         knhv::kNestedSecondaryEnableEpt},
        {"VMWRITE exit controls", knhv::kVmcsFieldExitControls, 0U},
        {"VMWRITE entry controls", knhv::kVmcsFieldEntryControls, 0U},
        {"VMWRITE guest CR0", knhv::kVmcsFieldGuestCr0, 0U},
        {"VMWRITE guest CR3", knhv::kVmcsFieldGuestCr3, 0U},
        {"VMWRITE guest CR4", knhv::kVmcsFieldGuestCr4, 0U},
        {"VMWRITE host CR0", knhv::kVmcsFieldHostCr0, 0U},
        {"VMWRITE host CR3", knhv::kVmcsFieldHostCr3, 0U},
        {"VMWRITE host CR4", knhv::kVmcsFieldHostCr4, 0U},
        {"VMWRITE guest RIP", knhv::kVmcsFieldGuestRip, 0x1000U},
        {"VMWRITE guest RSP", knhv::kVmcsFieldGuestRsp, 0x2000U},
        {"VMWRITE host RIP", knhv::kVmcsFieldHostRip, 0x3000U},
        {"VMWRITE host RSP", knhv::kVmcsFieldHostRsp, 0x4000U},
        {"VMWRITE guest RFLAGS", knhv::kVmcsFieldGuestRflags, 2U},
        {"VMWRITE EPTP", knhv::kVmcsFieldEptPointer, 0x5000U},
    };
    for (const VmcsWrite& write : entry_state) {
        if (!WriteVmcsField(device, request_id, session, write, state)) {
            return false;
        }
    }

    instruction = MakeInstruction(knhv::VmxOpcode::Vmlaunch);
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMLAUNCH", result, knhv::HvStatus::Success,
                      knhv::NestedAction::EnterL2)) {
        return false;
    }

    knhv::NestedExitRecord exit_record = {};
    exit_record.version = knhv::kNestedModelVersion;
    exit_record.size = static_cast<knhv::u32>(sizeof(exit_record));
    exit_record.reason = 10U;
    exit_record.instruction_length = 2U;
    exit_record.qualification = 0x1234U;
    if (!ReflectExit(device, (*request_id)++, session, exit_record, &result) ||
        !ExpectResult(state, "reflect first L2 exit", result,
                      knhv::HvStatus::Success,
                      knhv::NestedAction::ReflectVmexit)) {
        return false;
    }

    instruction = MakeInstruction(knhv::VmxOpcode::Vmread);
    instruction.flags = knhv::kInstructionOperandIsRegister;
    instruction.encoding = knhv::kVmcsFieldExitReason;
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMREAD exit reason", result,
                      knhv::HvStatus::Success,
                      knhv::NestedAction::ResumeL1) ||
        result.value != exit_record.reason) {
        if (result.value != exit_record.reason) {
            Check(state, "VMREAD returns reflected exit reason", false);
        }
        return false;
    }
    Check(state, "VMREAD returns reflected exit reason", true);

    instruction = MakeInstruction(knhv::VmxOpcode::Vmresume);
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMRESUME", result, knhv::HvStatus::Success,
                      knhv::NestedAction::EnterL2)) {
        return false;
    }

    exit_record.reason = 12U;
    if (!ReflectExit(device, (*request_id)++, session, exit_record, &result) ||
        !ExpectResult(state, "reflect second L2 exit", result,
                      knhv::HvStatus::Success,
                      knhv::NestedAction::ReflectVmexit)) {
        return false;
    }

    instruction = MakeInstruction(knhv::VmxOpcode::Vmxoff);
    if (!SendInstruction(device, (*request_id)++, session, instruction, &result) ||
        !ExpectResult(state, "VMXOFF", result, knhv::HvStatus::Success,
                      knhv::NestedAction::ResumeL1)) {
        return false;
    }
    return true;
}

void PrintUsage() {
    std::puts("KNHV_NestedProbe [--caps-only] [--device \\\\.\\KNHVNestedTest]");
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const wchar_t* device_name = kDefaultDeviceName;
    bool caps_only = false;
    for (int index = 1; index < argc; ++index) {
        if (std::wcscmp(argv[index], L"--help") == 0 ||
            std::wcscmp(argv[index], L"-h") == 0) {
            PrintUsage();
            return 0;
        }
        if (std::wcscmp(argv[index], L"--caps-only") == 0) {
            caps_only = true;
            continue;
        }
        if (std::wcscmp(argv[index], L"--device") == 0 && index + 1 < argc) {
            device_name = argv[++index];
            continue;
        }
        PrintUsage();
        return 2;
    }

    std::printf("KNHV nested software-contract probe: %ls\n", device_name);
    HANDLE device = CreateFileW(device_name, GENERIC_READ | GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        PrintWin32Failure("CreateFileW");
        std::puts("Hint: start KNHV-NestedTest and run this program as administrator.");
        return 2;
    }

    ProbeState state = {};
    knhv::u64 request_id = 1U;
    knhv::HvSessionKey session = {};
    bool session_registered = false;
    bool lease_acquired = false;
    knhv::HvOwnerLeaseV2 lease = {};
    bool sequence_completed = false;

    do {
        knhv::HvQueryCapsOut caps = {};
        if (!QueryCaps(device, request_id++, &caps)) {
            Check(&state, "query nested capabilities", false);
            break;
        }
        Check(&state, "query nested capabilities",
              caps.status == knhv::HvStatus::Success);
        const bool nested_capability =
            (caps.snapshot.feature_bits & knhv::kCapNestedVmx) != 0 &&
            (caps.snapshot.status_flags & knhv::kFlagNestedVmx) != 0;
        Check(&state, "nested VMX capability is advertised", nested_capability);
        Check(&state, "synthetic model is explicitly labeled",
              (caps.snapshot.status_flags & knhv::kFlagSyntheticSnapshot) != 0);
        knhv::HvQueryCapsV2Out caps_v2 = {};
        if (!QueryCapsV2(device, request_id++, &caps_v2)) {
            Check(&state, "query v2 nested capabilities", false);
            break;
        }
        Check(&state, "query v2 nested capabilities",
              caps_v2.status == knhv::HvStatus::Success &&
                  caps_v2.capabilities.owner_kind == static_cast<knhv::u32>(
                      knhv::HvOwnerKindV2::SyntheticLab) &&
                  caps_v2.capabilities.state == static_cast<knhv::u32>(
                      knhv::HvProviderStateV2::Available));
        std::printf("caps: features=0x%llX flags=0x%X evmcs=%u\n",
                    static_cast<unsigned long long>(caps.snapshot.feature_bits),
                    caps.snapshot.status_flags, caps.snapshot.e_vmcs_version);
        if (caps.status != knhv::HvStatus::Success || !nested_capability ||
            (caps.snapshot.status_flags &
             knhv::kFlagSyntheticSnapshot) == 0) {
            break;
        }
        if (caps_only) {
            sequence_completed = state.failed == 0;
            break;
        }

        knhv::HvRegisterClientOut registration = {};
        if (!RegisterClient(device, request_id++, &registration)) {
            Check(&state, "register known nested test provider", false);
            break;
        }
        const bool registration_ready =
            registration.status == knhv::HvStatus::Success &&
            registration.provider == knhv::HvProviderKind::CooperativeL1 &&
            registration.load_success != 0 &&
            registration.registration_ready != 0 && registration.client_id != 0 &&
            registration.generation != 0;
        Check(&state, "register known nested test provider", registration_ready);
        Check(&state, "synthetic session stays virtualization-ready false",
              registration.virtualization_ready == 0);
        if (!registration_ready) break;
        session.client_id = registration.client_id;
        session.generation = registration.generation;
        session_registered = true;

        knhv::HvSessionStatusOut session_status = {};
        if (!QuerySession(device, request_id++, session, &session_status)) {
            Check(&state, "query registered session", false);
            break;
        }
        Check(&state, "query registered session",
              session_status.status == knhv::HvStatus::Success &&
                  session_status.provider == knhv::HvProviderKind::CooperativeL1 &&
                  session_status.load_success != 0 &&
                  session_status.registration_ready != 0 &&
                  session_status.virtualization_ready == 0);

        knhv::HvAcquireLeaseV2Out lease_response = {};
        if (!AcquireSyntheticLease(device, request_id++, session,
                                   &lease_response)) {
            Check(&state, "acquire synthetic v2 lease", false);
            break;
        }
        Check(&state, "acquire synthetic v2 lease",
              lease_response.response.status == knhv::HvStatus::Success &&
                  lease_response.response.provider ==
                      knhv::HvProviderKind::CooperativeL1 &&
                  (lease_response.response.lease.flags &
                   knhv::kLeaseFlagSynthetic) != 0);
        if (lease_response.response.status != knhv::HvStatus::Success) break;
        lease = lease_response.response.lease;
        lease_acquired = true;

        sequence_completed =
            RunNestedSequence(device, &request_id, session, &state);
    } while (false);

    if (lease_acquired) {
        Check(&state, "release synthetic v2 lease",
              ReleaseLeaseV2(device, request_id++, session, lease));
    }
    if (session_registered) {
        Check(&state, "release nested session",
              ReleaseSession(device, request_id++, session));
    }
    CloseHandle(device);

    std::printf("\nSummary: %u passed, %u failed\n", state.passed, state.failed);
    if (sequence_completed && state.failed == 0) {
        std::puts("VERDICT: nested software contract passed.");
        return 0;
    }
    std::puts("VERDICT: nested software contract did not pass.");
    return 1;
}
