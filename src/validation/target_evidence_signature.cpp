#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>

#include <cstddef>
#include <cwchar>

#include "knhv_target_evidence_signature.h"

namespace knhv {
namespace {

bool IsVersionedSizeValid(u32 version, u32 size, u32 required) {
    return version == kTargetEvidenceSignatureContractVersion &&
           size >= required &&
           size <= kTargetEvidenceSignatureMaxStructSize;
}

bool IsStatusValid(u32 value) {
    return value <= static_cast<u32>(
                         TargetEvidenceSignatureStatus::VerificationUnavailable);
}

bool IsPathValid(const wchar_t* path) {
    if (path == nullptr || *path == L'\0') return false;
    std::size_t length = 0U;
    while (length <= kTargetEvidenceSignatureMaxPath &&
           path[length] != L'\0') {
        ++length;
    }
    return length <= kTargetEvidenceSignatureMaxPath;
}

void InitializeResult(TargetEvidenceSignatureResult* result) {
    *result = {};
    result->size = sizeof(*result);
    result->version = kTargetEvidenceSignatureContractVersion;
    result->status = static_cast<u32>(
        TargetEvidenceSignatureStatus::InvalidArgument);
}

bool IsPrivateTestRootStatus(LONG status) {
    return status == TRUST_E_SUBJECT_NOT_TRUSTED ||
           status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING ||
           status == CERT_E_UNTRUSTEDTESTROOT;
}

bool IsVerificationUnavailableStatus(LONG status) {
    return status == E_NOTIMPL || status == ERROR_CALL_NOT_IMPLEMENTED ||
           status == HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND) ||
           status == HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
}

TargetEvidenceSignatureStatus MapWinTrustStatus(LONG status,
                                                 bool allow_private_root,
                                                 u32& result_flags) {
    result_flags = 0U;
    if (status == ERROR_SUCCESS) {
        return TargetEvidenceSignatureStatus::Trusted;
    }
    if (status == TRUST_E_NOSIGNATURE ||
        status == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        status == TRUST_E_PROVIDER_UNKNOWN) {
        return TargetEvidenceSignatureStatus::NotSigned;
    }
    if (IsPrivateTestRootStatus(status)) {
        if (allow_private_root) {
            result_flags = kTargetEvidenceSignatureResultPrivateRootAccepted;
            return TargetEvidenceSignatureStatus::PrivateTestRoot;
        }
        return TargetEvidenceSignatureStatus::Untrusted;
    }
    if (IsVerificationUnavailableStatus(status)) {
        return TargetEvidenceSignatureStatus::VerificationUnavailable;
    }
    return TargetEvidenceSignatureStatus::Untrusted;
}

}  // namespace

bool IsTargetEvidenceSignatureRequestValid(
    const TargetEvidenceSignatureRequest* request) {
    return request != nullptr &&
           IsVersionedSizeValid(request->version, request->size,
                                sizeof(TargetEvidenceSignatureRequest)) &&
           (request->flags & ~kTargetEvidenceSignatureKnownFlagMask) == 0U &&
           request->reserved == 0U;
}

bool IsTargetEvidenceSignatureResultValid(
    const TargetEvidenceSignatureResult* result) {
    if (result == nullptr ||
        !IsVersionedSizeValid(result->version, result->size,
                              sizeof(TargetEvidenceSignatureResult)) ||
        !IsStatusValid(result->status) ||
        (result->result_flags &
         ~kTargetEvidenceSignatureResultPrivateRootAccepted) != 0U ||
        result->reserved != 0U) {
        return false;
    }

    const auto status = static_cast<TargetEvidenceSignatureStatus>(
        result->status);
    const bool private_root_accepted =
        (result->result_flags &
         kTargetEvidenceSignatureResultPrivateRootAccepted) != 0U;
    if (status == TargetEvidenceSignatureStatus::Trusted) {
        return result->wintrust_status == 0U && !private_root_accepted;
    }
    if (status == TargetEvidenceSignatureStatus::PrivateTestRoot) {
        return result->wintrust_status != 0U && private_root_accepted;
    }
    if (private_root_accepted) return false;
    switch (status) {
        case TargetEvidenceSignatureStatus::InvalidArgument:
        case TargetEvidenceSignatureStatus::FileNotFound:
            return result->wintrust_status == 0U;
        case TargetEvidenceSignatureStatus::NotSigned:
        case TargetEvidenceSignatureStatus::Untrusted:
        case TargetEvidenceSignatureStatus::VerificationUnavailable:
            return result->wintrust_status != 0U;
        default:
            return false;
    }
}

TargetEvidenceSignatureStatus VerifyTargetEvidenceFileSignature(
    const wchar_t* path, const TargetEvidenceSignatureRequest* request,
    TargetEvidenceSignatureResult* result) {
    if (result == nullptr) {
        return TargetEvidenceSignatureStatus::InvalidArgument;
    }
    InitializeResult(result);
    if (!IsTargetEvidenceSignatureRequestValid(request) ||
        !IsPathValid(path)) {
        return TargetEvidenceSignatureStatus::InvalidArgument;
    }

    const DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
        result->status = static_cast<u32>(
            TargetEvidenceSignatureStatus::FileNotFound);
        return TargetEvidenceSignatureStatus::FileNotFound;
    }

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path;

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG trust_status =
        WinVerifyTrust(nullptr, &policy, &trust_data);
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(nullptr, &policy, &trust_data);

    result->wintrust_status = static_cast<u32>(trust_status);
    const bool allow_private_root =
        (request->flags & kTargetEvidenceSignatureFlagAllowPrivateTestRoot) !=
        0U;
    const TargetEvidenceSignatureStatus mapped = MapWinTrustStatus(
        trust_status, allow_private_root, result->result_flags);
    result->status = static_cast<u32>(mapped);
    return mapped;
}

const char* TargetEvidenceSignatureStatusText(
    TargetEvidenceSignatureStatus status) {
    switch (status) {
        case TargetEvidenceSignatureStatus::Trusted:
            return "trusted";
        case TargetEvidenceSignatureStatus::InvalidArgument:
            return "invalid-argument";
        case TargetEvidenceSignatureStatus::FileNotFound:
            return "file-not-found";
        case TargetEvidenceSignatureStatus::NotSigned:
            return "not-signed";
        case TargetEvidenceSignatureStatus::Untrusted:
            return "untrusted";
        case TargetEvidenceSignatureStatus::PrivateTestRoot:
            return "private-test-root";
        case TargetEvidenceSignatureStatus::VerificationUnavailable:
            return "verification-unavailable";
        default:
            return "unknown";
    }
}

}  // namespace knhv
