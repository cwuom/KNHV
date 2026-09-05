#include "test_support.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace knhv_tests {
namespace {

std::string Source(const fs::path& root, std::string_view relative,
                   TestState& state) {
    return ReadText(root / relative, state);
}

void CheckLineLimits(const fs::path& root, TestState& state) {
    const std::array<fs::path, 3> roots = {root / "src", root / "tests",
                                           root / "tools"};
    for (const fs::path& directory : roots) {
        if (!fs::exists(directory)) continue;
        for (const fs::directory_entry& entry :
             fs::recursive_directory_iterator(directory)) {
            if (!entry.is_regular_file()) continue;
            const std::string extension = entry.path().extension().string();
            if (extension != ".cpp" && extension != ".h" &&
                extension != ".asm" && extension != ".inc" &&
                extension != ".ps1") {
                continue;
            }
            std::ifstream file(entry.path());
            const bool readable = file.good();
            std::size_t line_count = 0;
            std::string line;
            while (std::getline(file, line)) ++line_count;
            const bool read_complete = !file.bad();
            Check(state, "file stays below 2000 lines",
                  readable && read_complete && line_count <= 2000,
                  entry.path().generic_string());
        }
    }
}

void CheckNoStaleReferenceNames(const fs::path& root, TestState& state) {
    const std::array<fs::path, 2> roots = {root / "src", root / "tests"};
    bool clean = true;
    std::string first_match;
    for (const fs::path& directory : roots) {
        if (!fs::exists(directory)) continue;
        for (const fs::directory_entry& entry :
             fs::recursive_directory_iterator(directory)) {
            if (!entry.is_regular_file()) continue;
            const std::string content = ReadText(entry.path(), state);
            const std::string forbidden = std::string("Hyper") + "Dbg";
            if (content.find(forbidden) != std::string::npos ||
                content.find("hyper" + std::string("dbg")) !=
                    std::string::npos) {
                clean = false;
                if (first_match.empty()) first_match = entry.path().string();
            }
        }
    }
    Check(state, "implementation has no stale reference-project names", clean,
          first_match);
}

void CheckProjectIdentity(const fs::path& root, TestState& state) {
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    const std::string presets = Source(root, "CMakePresets.json", state);
    const std::string settings = Source(root, ".vscode/settings.json", state);
    const std::string readme = Source(root, "README.md", state);

    Check(state, "build targets use the KNHV identity",
          Contains(cmake, "project(KNHV") &&
              Contains(cmake, "wdk_add_driver(KNHV") &&
              Contains(cmake, "KNHV_ContractTests") &&
              Contains(cmake, "KNHV_FAULT_INJECTION") &&
              Contains(cmake, "OBJECT_DEPENDS") &&
              Contains(cmake, "vmx_asm.inc") &&
              Contains(presets, "KNHV Debug") &&
              Contains(presets, "KNHV.sys"));
    Check(state, "editor configuration resolves KNHV headers through CMake",
          Contains(settings, "${workspaceFolder}/src/include") &&
              Contains(settings, "compile_commands.json"));
    Check(state, "README documents the current project name and layout",
          Contains(readme, "# KNHV") && Contains(readme, "src/core") &&
              Contains(readme, "src/vmx") && Contains(readme, "KNHV.sys"));
    Check(state, "nested driver targets remain independently buildable",
          Contains(cmake, "KNHV_BUILD_NESTED_DRIVERS") &&
              Contains(cmake, "KNHV_Control") &&
              Contains(cmake, "KNHV_NestedTest") &&
              Contains(cmake, "KNHV-Control") &&
              Contains(cmake, "KNHV-NestedTest"));
    Check(state, "kernel targets enforce W4 and warnings as errors",
          Contains(cmake, ":/W4>") && Contains(cmake, ":/WX>"));
}

void CheckNestedImplementation(const fs::path& root, TestState& state) {
    const std::string abi = Source(root, "src/include/knhv_abi.h", state);
    const std::string nested = Source(root, "src/include/knhv_nested.h", state);
    const std::string vmcs = Source(root, "src/nested/nested_vmcs.cpp", state);
    const std::string instructions =
        Source(root, "src/nested/nested_instructions.cpp", state);
    const std::string boot = Source(root, "src/boot/boot_contract.cpp", state);
    const std::string control =
        Source(root, "src/control/control_device.cpp", state);
    const std::string ioctl =
        Source(root, "src/include/knhv_control_ioctl.h", state);
    const std::string readme = Source(root, "README.md", state);
    Check(state, "nested ABI is versioned and size checked",
          Contains(abi, "kAbiVersion") &&
              Contains(abi, "IsVersionedBufferValid") &&
              Contains(abi, "kFlagSyntheticSnapshot") &&
              Contains(abi, "struct HvSessionKey") &&
              Contains(nested, "struct NestedVcpu"));
    Check(state, "VMCS12 field rules enforce control masks",
          Contains(vmcs, "reserved_zero_mask") &&
              Contains(vmcs, "(requested | allowed0) & allowed1") &&
              Contains(vmcs, "ValidateEntryState"));
    Check(state, "nested instruction dispatch separates VMfail and #UD",
          Contains(instructions, "Vmxon") &&
              Contains(instructions, "InjectUndefinedInstruction") &&
              Contains(instructions, "ReflectNestedExit"));
    Check(state, "BootL0 contract records owner uniqueness and recovery",
          Contains(boot, "owner_count") && Contains(boot, "Recovery") &&
              Contains(boot, "HandoffWindows"));
    Check(state, "control device uses buffered IO and a restricted ACL",
          Contains(ioctl, "METHOD_BUFFERED") &&
              Contains(control, "SDDL_DEVOBJ_SYS_ALL_ADM_ALL") &&
              Contains(control, "IoAcquireRemoveLock") &&
              Contains(control, "VersionedInputFits") &&
              Contains(ioctl, "IOCTL_KNHV_RELEASE_SESSION") &&
              Contains(control, "KnHvDispatchUnsupported") &&
              Contains(control, "owner_file") &&
              Contains(control, "ReleaseSessionsForFile") &&
              Contains(control, "owner_file->FsContext != owner_file"));
    const std::size_t handler_begin = control.find("NTSTATUS HandleQueryCaps");
    const std::size_t dispatch_begin =
        control.find("extern \"C\" NTSTATUS KnHvDispatchCreate");
    const bool handlers_defer_completion =
        handler_begin != std::string::npos &&
        dispatch_begin != std::string::npos && dispatch_begin > handler_begin &&
        control.substr(handler_begin, dispatch_begin - handler_begin)
                .find("CompleteIrp") == std::string::npos;
    Check(state, "remove lock is released before IRP completion",
          handlers_defer_completion &&
              ContainsInOrder(control,
                              {"const ULONG_PTR information = irp->IoStatus.Information;",
                               "IoReleaseRemoveLock(&extension->remove_lock, irp);",
                               "return CompleteIrp(irp, result, information);"}));

    const std::string control_inf =
        Source(root, "drivers/control/KNHV-Control.inf", state);
    const std::string nested_inf =
        Source(root, "drivers/nested_test/KNHV-NestedTest.inf", state);
    Check(state, "the two driver packages have separate services",
          Contains(control_inf, "AddService=KNHV-Control") &&
              Contains(nested_inf, "AddService=KNHV-NestedTest") &&
              Contains(control_inf, "KNHV-Control.cat") &&
              Contains(nested_inf, "KNHV-NestedTest.cat"));
    Check(state, "auxiliary driver packages run from the Driver Store",
          Contains(control_inf, "PnpLockdown=1") &&
              Contains(control_inf, "DriverCopyFiles=13") &&
              Contains(control_inf, "ServiceBinary=%13%\\KNHV-Control.sys") &&
              Contains(nested_inf, "PnpLockdown=1") &&
              Contains(nested_inf, "DriverCopyFiles=13") &&
              Contains(nested_inf,
                       "ServiceBinary=%13%\\KNHV-NestedTest.sys"));
    Check(state, "auxiliary drivers do not execute physical VMXON",
          Contains(control, "MakeFallbackCapabilitySnapshot") &&
              !Contains(control, "__vmx_on") &&
              !Contains(control, "__writemsr"));
    Check(state, "synthetic nested capability is laboratory-only",
          Contains(readme, "kFlagSyntheticSnapshot") &&
              Contains(readme, "laboratory-only") &&
              Contains(readme, "file-object binding") &&
              Contains(readme, "does not verify") &&
              Contains(control, "synthetic_model") &&
              Contains(control, "virtualization_ready") &&
              Contains(control, "!synthetic_model"));
}

void CheckModuleBoundaries(const fs::path& root, TestState& state) {
    struct ModuleContract {
        std::string_view file;
        std::array<std::string_view, 2> symbols;
    };
    const std::array<ModuleContract, 10> modules = {{
        {"src/core/vmm.cpp", {"StartHypervisor", "StopHypervisorInternal"}},
        {"src/core/vmm_state.cpp", {"g_HvLifecycle", "WriteHvTrace"}},
        {"src/vmx/vmx_features.cpp",
         {"InitializeVmxFeatureContract", "BuildVmxCapabilityProfile"}},
        {"src/vmx/vmx_diagnostics.cpp",
         {"VmWriteChecked", "IsValidGuestState"}},
        {"src/vmx/vmx_crash.cpp",
         {"CaptureHvCrashBlob", "RegisterSecondaryDumpCallback"}},
        {"src/vmx/vmx_teardown_state.cpp",
         {"HvClearCurrentVmcsAndRecord", "UpdateNativeTeardownContract"}},
        {"src/vmx/vmx_exit.cpp", {"VmExitHandler", "HandleMsrRead"}},
        {"src/vmx/vmx_vmcs.cpp", {"SetupVmcs", "GetTssBase"}},
        {"src/vmx/vmx_launch.cpp",
         {"PrepareHvCallback", "LaunchBroadcastDpcRoutine"}},
        {"src/vmx/vmx_stop.cpp", {"StopHvCallback", "QueueTargetOperation"}},
    }};

    for (const ModuleContract& module : modules) {
        const std::string content = Source(root, module.file, state);
        bool present = !content.empty();
        for (const std::string_view symbol : module.symbols) {
            present = present && Contains(content, symbol);
        }
        Check(state, "module owns its declared responsibility", present,
              module.file);
    }

    const std::string facade = Source(root, "src/core/vmm.cpp", state);
    Check(state, "lifecycle facade remains compact",
          std::count(facade.begin(), facade.end(), '\n') <= 2000,
          "src/core/vmm.cpp");
}

void CheckPublicInterface(const fs::path& root, TestState& state) {
    const std::string header = Source(root, "src/include/vmm.h", state);
    const std::array<std::string_view, 7> api = {
        "extern \"C\" NTSTATUS StartHypervisor();",
        "extern \"C\" void StopHypervisor();",
        "extern \"C\" bool IsHypervisorStopComplete();",
        "extern \"C\" bool IsHypervisorQuarantined();",
        "extern \"C\" void QuarantineHypervisorImage();",
        "bool InitializeVmxFeatureContract();",
        "u32 GetXsaveStateSize();",
    };
    bool complete = true;
    for (const std::string_view declaration : api) {
        complete = complete && Contains(header, declaration);
    }
    Check(state, "public lifecycle API is explicit", complete,
          "src/include/vmm.h");
    Check(state, "public header does not include implementation",
          !Contains(header, "vmm_internal.h"), "src/include/vmm.h");
}

std::string AssemblySources(const fs::path& root, TestState& state) {
    static constexpr std::array<std::string_view, 4> kAssemblyFiles = {
        "src/asm/vmx_asm.inc",
        "src/asm/vmx_entry.asm",
        "src/asm/vmx_instructions.asm",
        "src/asm/vmx_launch.asm",
    };
    std::string result;
    for (const std::string_view relative : kAssemblyFiles) {
        result.append("\n; source: ");
        result.append(relative);
        result.push_back('\n');
        result.append(ReadText(root / relative, state));
    }
    return result;
}

void CheckAssemblyContract(const fs::path& root, TestState& state) {
    const std::string assembly = AssemblySources(root, state);
    const bool split = !fs::exists(root / "src/asm/arch.asm") &&
                       fs::exists(root / "src/asm/vmx_asm.inc") &&
                       fs::exists(root / "src/asm/vmx_entry.asm") &&
                       fs::exists(root / "src/asm/vmx_instructions.asm") &&
                       fs::exists(root / "src/asm/vmx_launch.asm");
    Check(state, "assembly is split by responsibility", split,
          "src/asm");
    const std::array<std::string_view, 11> required = {
        "PUBLIC HvVmWrite",
        "vmwrite rcx, rdx",
        "PUBLIC HvVmReadChecked",
        "vmread r8, rcx",
        "xsaves64 [rsp]",
        "xrstors64 [rsp]",
        "call VmExitHandler",
        "call HvClearCurrentVmcsAndRecord",
        "call HvCaptureFatalSnapshotPreVmxoff",
        "call MarkCurrentVcpuParked",
        "call HvFatalBugCheck",
    };
    bool complete = true;
    for (const std::string_view token : required) {
        complete = complete && Contains(assembly, token);
    }
    Check(state, "assembly and C++ use the documented ABI", complete,
          "src/asm");
    const std::size_t vmwrite_begin = assembly.find("HvVmWrite proc");
    const std::size_t vmwrite_end =
        assembly.find("HvVmWrite endp", vmwrite_begin);
    const std::string vmwrite =
        vmwrite_begin != std::string::npos && vmwrite_end > vmwrite_begin
            ? assembly.substr(vmwrite_begin, vmwrite_end - vmwrite_begin)
            : std::string{};
    Check(state, "VMWRITE keeps field and value in the C++ ABI order",
          Contains(vmwrite, "vmwrite rcx, rdx") &&
              !Contains(vmwrite, "vmwrite rdx, rcx"),
          "RCX=field, RDX=value");
    const std::string internal =
        Source(root, "src/include/vmm_internal.h", state);
    const std::string diagnostics =
        Source(root, "src/vmx/vmx_diagnostics.cpp", state);
    Check(state, "VMWRITE call sites preserve the field-value contract",
          Contains(internal, "u64 HvVmWrite(u64 field, u64 value)") &&
              ContainsInOrder(diagnostics,
                              {"HvVmWrite(field, value)",
                               "const bool success = VmxOk(flags)"}),
          "field is passed in RCX and value in RDX");
    Check(state, "assembly has no old reference-project symbol",
          assembly.find(std::string("Hyper") + "Dbg") == std::string::npos &&
              assembly.find("hyper" + std::string("dbg")) ==
                  std::string::npos);

    const std::string common = Source(root, "src/include/common.h", state);
    Check(state, "guest frame offsets are guarded by static assertions",
          std::count(common.begin(), common.end(), '\n') > 0 &&
              Contains(common, "offsetof(GuestContext, Rax) == 0x1000") &&
              Contains(common, "offsetof(GuestContext, GuestXcr0) == 0x1108") &&
              Contains(common, "sizeof(GuestContext) <= 0x1178"));
}

void CheckFeatureGates(const fs::path& root, TestState& state) {
    const std::string main = Source(root, "src/core/main.cpp", state);
    const std::string features = Source(root, "src/vmx/vmx_features.cpp", state);
    const std::string exit = Source(root, "src/vmx/vmx_exit.cpp", state);
    const std::string vmcs = Source(root, "src/vmx/vmx_vmcs.cpp", state);
    const std::string internal = Source(root, "src/include/vmm_internal.h", state);

    Check(state, "vendor is checked before VMX capability reads",
          ContainsInOrder(main, {"genuineIntel", "VMX_BASIC"}));
    Check(state, "firmware VMX policy is never provisioned by the driver",
          !Contains(main, "__writemsr(MSR_IA32_FEATURE_CONTROL") &&
              Contains(main, "IA32_FEATURE_CONTROL_VMXON_OUTSIDE_SMX"));
    Check(state, "legacy floating-point state has a fail-closed gate",
          Contains(main, "CR0.EM or CR0.TS") &&
              Contains(main, "CPUID_1_EDX_FXSR"));
    Check(state, "feature contract is sticky for one run",
          Contains(features, "g_VmxFeatureContractInitialized") &&
              Contains(features, "g_VmxFeatureContractValid"));
    Check(state, "XSAVES uses one immutable host mask",
          Contains(features, "g_XsavesMask") &&
              Contains(features, "g_HostXssMask"));
    Check(state, "CET entry and exit controls are paired",
          Contains(features, "VM_EXIT_LOAD_CET_STATE") &&
              Contains(features, "VM_ENTRY_LOAD_CET_STATE") &&
              Contains(vmcs, "HOST_S_CET") && Contains(vmcs, "GUEST_S_CET"));
    Check(state, "unsupported guest MSRs are intercepted",
          Contains(exit, "IsIntelPtMsr") && Contains(exit, "IsCetStateMsr") &&
              Contains(exit, "ConfigureMsrBitmap"));
    Check(state, "optional instructions use an all-CPU profile",
          Contains(internal, "kGuestOptionalProfileMask") &&
              Contains(Source(root, "src/core/vmm.cpp", state),
                       "g_VmxGuestOptionalProfileCandidate"));
}

void CheckTeardownContract(const fs::path& root, TestState& state) {
    const std::string lifecycle = Source(root, "src/core/vmm.cpp", state);
    const std::string stop = Source(root, "src/vmx/vmx_stop.cpp", state);
    const std::string teardown =
        Source(root, "src/vmx/vmx_teardown_state.cpp", state);
    const std::string crash = Source(root, "src/vmx/vmx_crash.cpp", state);
    const std::string assembly = AssemblySources(root, state);

    Check(state, "start claims the lifecycle with an atomic transition",
          ContainsInOrder(lifecycle, {"kHvLifecycleStarting",
                                       "InterlockedCompareExchange"}));
    Check(state, "stop uses finite target deadlines and retries",
          Contains(stop, "kTargetOperationTimeout100ns") &&
              Contains(stop, "kStopRetryLimit") &&
              Contains(stop, "WaitTargetOperation"));
    Check(state, "unresolved work enters quarantine",
          ContainsInOrder(lifecycle, {"HasUnresolvedTargetWork()",
                                       "PinImageForParkedCpu()",
                                       "kHvLifecycleQuarantined"}));
    Check(state, "resource reclamation follows VMCS ownership checks",
          Contains(lifecycle, "HasUnclearedVmcs()") &&
              ContainsInOrder(lifecycle, {"HasUnclearedVmcs()", "MmFreeContiguousMemory"}));
    Check(state, "native teardown validates the descriptor contract",
          Contains(teardown, "UpdateNativeTeardownContract") &&
              Contains(teardown, "IsNativeTeardownSegmentValid"));
    Check(state, "fatal assembly path records before VMXOFF",
          ContainsInOrder(assembly, {"HvCaptureFatalSnapshotPreVmxoff",
                                     "MarkCurrentVcpuParked", "vmxoff"}));
    Check(state, "native allocations use the current WDK pool API",
          Contains(lifecycle, "ExAllocatePool2") &&
              !Contains(lifecycle, "ExAllocatePoolWithTag") &&
              Contains(crash, "ExAllocatePool2") &&
              !Contains(crash, "ExAllocatePoolWithTag"));
}

void CheckFaultInjectionContract(const fs::path& root, TestState& state) {
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    const std::string internal = Source(root, "src/include/vmm_internal.h", state);
    const std::string state_source = Source(root, "src/core/vmm_state.cpp", state);
    Check(state, "fault injection is opt-in at configure time",
          Contains(cmake, "KNHV_FAULT_INJECTION") &&
              Contains(cmake, "KNHV_TEST_FAIL_CPU") &&
              Contains(cmake, "KNHV_TEST_FAIL_STAGE"));
    Check(state, "fault stages are named and bounded",
          Contains(internal, "HvFaultBeforeVmxon") &&
              Contains(internal, "HvFaultTeardown") &&
              Contains(state_source, "ShouldInjectFault"));
}

void CheckPureModels(TestState& state) {
    struct MsrBitmap {
        std::array<std::uint8_t, 0x1000> bytes{};

        static bool Resolve(std::uint32_t msr, bool write,
                            std::size_t& offset, std::uint8_t& mask) {
            std::uint32_t normalized = msr;
            std::uint32_t region = 0;
            if (msr <= 0x1FFFU) {
                region = write ? 0x800U : 0U;
            } else if (msr >= 0xC0000000U && msr <= 0xC0001FFFU) {
                region = write ? 0xC00U : 0x400U;
                normalized -= 0xC0000000U;
            } else {
                return false;
            }
            offset = region + ((normalized & 0x1FFFU) >> 3);
            mask = static_cast<std::uint8_t>(1U << (normalized & 7U));
            return offset < 0x1000U;
        }

        bool Set(std::uint32_t msr, bool write) {
            std::size_t offset = 0;
            std::uint8_t mask = 0;
            if (!Resolve(msr, write, offset, mask)) return false;
            bytes[offset] |= mask;
            return true;
        }

        bool IsSet(std::uint32_t msr, bool write) const {
            std::size_t offset = 0;
            std::uint8_t mask = 0;
            return Resolve(msr, write, offset, mask) &&
                   (bytes[offset] & mask) != 0;
        }

    } bitmap;

    Check(state, "MSR model accepts the low boundary", bitmap.Set(0, false));
    Check(state, "MSR model accepts the high boundary",
          bitmap.Set(0xC0001FFFU, true));
    Check(state, "MSR model separates read and write regions",
          bitmap.Set(0x1FFFU, false) && !bitmap.IsSet(0x1FFFU, true));
    Check(state, "MSR model rejects unsupported indices",
          !bitmap.Set(0x2000U, false) && !bitmap.Set(0x80000000U, true));

    const auto valid_xsave_mask = [](std::uint64_t mask,
                                     std::uint64_t supported) {
        return (mask & 3ULL) == 3ULL && (mask & ~supported) == 0;
    };
    Check(state, "XSTATE model requires x87 and SSE",
          !valid_xsave_mask(1ULL, 0x7ULL) &&
              valid_xsave_mask(0x7ULL, 0x7ULL));
    Check(state, "XSTATE model rejects an unenumerated component",
          !valid_xsave_mask(0xFULL, 0x7ULL));
}

}  // namespace

void RunSourceContract(const fs::path& root, TestState& state) {
    CheckLineLimits(root, state);
    CheckNoStaleReferenceNames(root, state);
    CheckProjectIdentity(root, state);
    CheckNestedImplementation(root, state);
    CheckModuleBoundaries(root, state);
    CheckPublicInterface(root, state);
    CheckAssemblyContract(root, state);
    CheckFeatureGates(root, state);
    CheckTeardownContract(root, state);
    CheckFaultInjectionContract(root, state);
    CheckPureModels(state);
    RunNestedModelContract(root, state);
}

}  // namespace knhv_tests
