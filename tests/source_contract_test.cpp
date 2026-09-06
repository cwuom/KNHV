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
    const std::array<fs::path, 6> roots = {
        root / "src", root / "tests", root / "tools",
        root / "HV_PROBE_TESTER", root / "benchmarks", root / "preflight"};
    for (const fs::path& directory : roots) {
        if (!fs::exists(directory)) continue;
        for (const fs::directory_entry& entry :
             fs::recursive_directory_iterator(directory)) {
            if (!entry.is_regular_file()) continue;
            const std::string extension = entry.path().extension().string();
            if (extension != ".cpp" && extension != ".h" &&
                extension != ".asm" && extension != ".inc" &&
                extension != ".ps1" && extension != ".bat") {
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
    const std::string build_script =
        Source(root, "tools/Build-Driver.ps1", state);
    const std::string standalone_script =
        Source(root, "HV_PROBE_TESTER/build_msvc.bat", state);

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
    const std::string nested_probe =
        Source(root, "HV_PROBE_TESTER/nested_probe.cpp", state);
    Check(state, "nested probe uses the public device ABI",
          Contains(cmake, "KNHV_NestedProbe") &&
              Contains(presets, "KNHV_NestedProbe") &&
              Contains(nested_probe, "CreateFileW") &&
              Contains(nested_probe, "IOCTL_KNHV_NESTED_INSTRUCTION") &&
              Contains(nested_probe, "IOCTL_KNHV_REFLECT_EXIT"));
    const std::string native_probe =
        Source(root, "HV_PROBE_TESTER/native_vmx_probe.cpp", state);
    Check(state, "native probe is named and classified by the build",
          !fs::exists(root / "HV_PROBE_TESTER/hv_probe.cpp") &&
              Contains(native_probe, "kProbeLeaf") &&
              Contains(cmake, "KNHV_NativeVmxProbe") &&
              Contains(presets, "KNHV_NativeVmxProbe") &&
              Contains(cmake, "KNHV_ARTIFACT_ROOT") &&
              Contains(cmake, "RUNTIME_OUTPUT_DIRECTORY") &&
              Contains(cmake, "PDB_OUTPUT_DIRECTORY") &&
              Contains(cmake, "/INCREMENTAL:NO") &&
              Contains(readme, "bin/KNHV_NativeVmxProbe.exe") &&
              Contains(readme, "sys/KNHV.sys"));
    Check(state, "build helpers preserve the artifact layout",
          Contains(build_script, "KNHV_ARTIFACT_ROOT") &&
              Contains(build_script, "Join-Path $BuildDirectory \"sys\"") &&
              Contains(build_script, "Join-Path $BuildDirectory \"bin\"") &&
              Contains(build_script, "KNHV_NativeVmxProbe.exe") &&
              Contains(standalone_script, "native_vmx_probe.cpp") &&
              Contains(standalone_script, "build\\standalone") &&
              Contains(standalone_script, "/Fo:") &&
              Contains(standalone_script, "/INCREMENTAL:NO") &&
              Contains(standalone_script, "KNHV_NativeVmxProbe.exe"));
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
    Check(state, "large session cleanup avoids stack temporaries",
          Contains(control, "RtlZeroMemory(session, sizeof(*session));") &&
              !Contains(control, "extension->sessions[index] = {};") &&
              !Contains(control, "*session = {};"));
    Check(state, "nested vcpu initialization avoids stack temporaries",
          Contains(vmcs, "bytes[index] = 0;") &&
              !Contains(vmcs, "*vcpu = {};"));
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

void CheckBenchmarkContract(const fs::path& root, TestState& state) {
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    const std::string build_script =
        Source(root, "tools/Build-Driver.ps1", state);
    const std::string run_script =
        Source(root, "tools/Run-Benchmarks.ps1", state);
    const std::string readme = Source(root, "README.md", state);
    const std::string common = Source(root, "benchmarks/bench_common.cpp", state);
    const std::array<std::string_view, 5> names = {
        "KNHV_NativeLikeBench", "KNHV_VmxExitBench", "KNHV_TscQpcBench",
        "KNHV_EptHookBench", "KNHV_DeviceIoBench"};
    bool targets_present = Contains(cmake, "KNHV_BUILD_BENCHMARKS") &&
                           Contains(cmake, "bcrypt") &&
                           Contains(cmake, "KNHV_BENCH_GIT");
    bool artifacts_documented = true;
    for (const std::string_view name : names) {
        targets_present = targets_present && Contains(cmake, name);
        artifacts_documented =
            artifacts_documented && Contains(build_script, std::string(name) + ".exe") &&
            Contains(readme, std::string(name) + ".exe");
    }
    Check(state, "benchmark targets and artifact layout are explicit",
          targets_present && artifacts_documented);
    Check(state, "benchmark sources are present and user-mode only",
          fs::exists(root / "benchmarks/bench_common.h") &&
              fs::exists(root / "benchmarks/bench_common.cpp") &&
              !Contains(common, "__vmx") && !Contains(common, "__writemsr") &&
              Contains(common, "knhv-bench-1"));
    Check(state, "benchmark candidate mode fails closed",
          Contains(common, "KNHVControl") &&
              Contains(common, "KNHV_BOOT_L0") &&
              Contains(common, "not-comparable") &&
              Contains(common, "kExitBlocked"));
    Check(state, "benchmark runner records reproducible provenance",
          Contains(run_script, "knhv-bench-run-1") &&
              Contains(run_script, "expected_exit_code") &&
              Contains(run_script, "physical_dma_enabled") &&
              Contains(run_script, "SkipNativeGate"));
}

void CheckPreflightContract(const fs::path& root, TestState& state) {
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    const std::string build_script =
        Source(root, "tools/Build-Driver.ps1", state);
    const std::string readme = Source(root, "README.md", state);
    const std::string common =
        Source(root, "preflight/preflight_common.cpp", state);
    const std::string header = Source(root, "preflight/preflight.h", state);
    Check(state, "preflight target and artifact are explicit",
          Contains(cmake, "KNHV_BUILD_PREFLIGHT") &&
              Contains(cmake, "KNHV_Preflight") &&
              Contains(cmake, "preflight/preflight_common.cpp") &&
              Contains(build_script, "KNHV_Preflight.exe") &&
              Contains(readme, "KNHV_Preflight.exe"));
    Check(state, "preflight is read-only and fail-closed",
          Contains(header, "GateState") &&
              Contains(common, "knhv-preflight-1") &&
              Contains(common, "EnumSystemFirmwareTables") &&
              Contains(common, "0x52414D44U") &&
              Contains(common, "DeviceIoControl") &&
              Contains(common, "IA32_FEATURE_CONTROL") &&
              Contains(common, "kExitBlocked") &&
              !Contains(common, "__vmx") && !Contains(common, "__writemsr"));
}

void CheckEptTimeContract(const fs::path& root, TestState& state) {
    const std::string ept_header = Source(root, "src/include/knhv_ept.h", state);
    const std::string ept_source = Source(root, "src/ept/ept_model.cpp", state);
    const std::string time_header = Source(root, "src/include/knhv_time.h", state);
    const std::string time_source = Source(root, "src/time/time_contract.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "EPT model exposes bounded pointer and mapping contracts",
          Contains(ept_header, "EptpConfig") &&
              Contains(ept_header, "ResolveNestedEpt") &&
              Contains(ept_header, "CanPublishEptHook") &&
              Contains(ept_source, "kEptPhysicalAddressMask") &&
              Contains(ept_source, "kEptMappingFlagHostOwned"));
    Check(state, "EPT model publishes generations only after acknowledgements",
          Contains(ept_source, "BeginEptGeneration") &&
              Contains(ept_source, "AcknowledgeEptGeneration") &&
              Contains(ept_source, "PublishEptGeneration"));
    Check(state, "time model uses fixed-point transforms and monotonic gates",
          Contains(time_header, "TscTransform") &&
              Contains(time_header, "ComposeTscTransforms") &&
              Contains(time_source, "_umul128") &&
              Contains(time_source, "DriftExceeded") &&
              Contains(time_source, "kTimeFlagMonotonicClamp"));
    Check(state, "EPT and time models are shared by the build graph",
          Contains(cmake, "src/ept/ept_model.cpp") &&
              Contains(cmake, "src/time/time_contract.cpp") &&
              Contains(cmake, "tests/ept_time_model_test.cpp"));
    Check(state, "pure EPT and time models contain no physical VMX instructions",
          !Contains(ept_source, "__vmx") && !Contains(ept_source, "__writemsr") &&
              !Contains(time_source, "__vmx") &&
              !Contains(time_source, "__writemsr"));
}

void CheckVmcs02Contract(const fs::path& root, TestState& state) {
    const std::string header = Source(root, "src/include/knhv_vmcs02.h", state);
    const std::string source = Source(root, "src/nested/vmcs02_model.cpp", state);
    const std::string test = Source(root, "tests/vmcs02_model_test.cpp", state);
    Check(state, "VMCS02 model exposes a separate image and policy",
          Contains(header, "Vmcs12Model") &&
              Contains(header, "Vmcs02Policy") &&
              Contains(header, "Vmcs02Image") &&
              Contains(source, "BuildVmcs02Model"));
    Check(state, "VMCS02 model applies allowed masks and fixed CR checks",
          Contains(source, "AdjustControl") &&
              Contains(source, "IsFixedCrValid") &&
              Contains(source, "kVmcs02PrimaryActivateSecondary"));
    Check(state, "VMCS02 tests cover success and fail-closed paths",
              Contains(test, "applies the L0 policy") &&
              Contains(test, "invalid EPTP") &&
              Contains(test, "contradictory policy controls"));
    Check(state, "VMCS02 model cannot execute physical VMX instructions",
          !Contains(source, "__vmx") && !Contains(source, "__writemsr") &&
              !Contains(source, "VMWRITE") && !Contains(source, "VMLAUNCH"));
    Check(state, "VMCS02 reader checks vCPU VMCS pointer ownership",
          Contains(source, "IsVmcsPointerOwned") &&
              Contains(test, "pointer outside the vCPU table"));
}

void CheckIommuContract(const fs::path& root, TestState& state) {
    const std::string header = Source(root, "src/include/knhv_iommu.h", state);
    const std::string source = Source(root, "src/iommu/iommu_model.cpp", state);
    const std::string test = Source(root, "tests/iommu_model_test.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "IOMMU model exposes device, domain, and mapping contracts",
          Contains(header, "IommuDeviceProfile") &&
              Contains(header, "IommuDomain") &&
              Contains(header, "IommuDmaMapping") &&
              Contains(source, "PrepareIommuAssignment"));
    Check(state, "IOMMU assignment enforces isolation, reset, and generation",
          Contains(source, "kIommuDeviceHasRmrr") &&
              Contains(source, "kIommuDeviceResetReliable") &&
              Contains(source, "GenerationMismatch") &&
              Contains(source, "QuarantineIommuAssignment"));
    Check(state, "nested DMA translation is fail-closed",
          Contains(source, "ResolveNestedDma") &&
              Contains(source, "kIommuMappingHostOwned") &&
              Contains(test, "nested DMA translation") &&
              Contains(test, "unpinned DMA mappings"));
    Check(state, "IOMMU model is wired into drivers and host tests",
          Contains(cmake, "src/iommu/iommu_model.cpp") &&
              Contains(cmake, "tests/iommu_model_test.cpp"));
    Check(state, "IOMMU model performs no physical device or VMX access",
          !Contains(source, "IoGetDmaAdapter") &&
              !Contains(source, "MmMapIoSpace") &&
              !Contains(source, "DeviceIoControl") &&
              !Contains(source, "__vmx") && !Contains(source, "__writemsr"));
}

void CheckExitContract(const fs::path& root, TestState& state) {
    const std::string header = Source(root, "src/include/knhv_exit.h", state);
    const std::string source = Source(root, "src/exit/exit_model.cpp", state);
    const std::string test = Source(root, "tests/exit_model_test.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "exit model separates policy, records, and decisions",
          Contains(header, "ExitPolicy") && Contains(header, "ExitRecord") &&
              Contains(header, "ExitDecision") &&
              Contains(source, "EvaluateExit"));
    Check(state, "exit model reflects approved VMX and EPT paths",
          Contains(source, "kExitPolicyReflectVmx") &&
              Contains(source, "kExitPolicyReflectEpt") &&
              Contains(source, "ReflectToL1"));
    Check(state, "exit model quarantines unknown and host-owned exits",
          Contains(source, "ExitClass::Unknown") &&
              Contains(source, "kExitRecordHostOwned") &&
              Contains(test, "unknown exits never resume"));
    Check(state, "exit model is included in driver and host test graphs",
          Contains(cmake, "src/exit/exit_model.cpp") &&
              Contains(cmake, "tests/exit_model_test.cpp"));
    Check(state, "exit model executes no VMX or device operation",
          !Contains(source, "__vmx") && !Contains(source, "__writemsr") &&
              !Contains(source, "DeviceIoControl"));
}

void CheckCpuPolicyContract(const fs::path& root, TestState& state) {
    const std::string header =
        Source(root, "src/include/knhv_cpu_policy.h", state);
    const std::string source =
        Source(root, "src/vmx/cpu_policy_model.cpp", state);
    const std::string test =
        Source(root, "tests/cpu_policy_model_test.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "CPU policy model exposes bounded CPUID and MSR rules",
          Contains(header, "CpuidPolicy") && Contains(header, "MsrPolicy") &&
              Contains(header, "FilterCpuid") &&
              Contains(source, "EvaluateMsrAccess"));
    Check(state, "CPU policy hides unsupported VMX and topology state",
          Contains(source, "kCpuidExposeVmx") &&
              Contains(source, "kCpuidPreserveTopology") &&
              Contains(test, "hides VMX") &&
              Contains(test, "hides topology"));
    Check(state, "CPU policy fails closed for unknown or sensitive MSRs",
          Contains(source, "InjectGeneralProtection") &&
              Contains(source, "kMsrIa32Efer") &&
              Contains(test, "unknown MSRs") &&
              Contains(test, "sensitive EFER"));
    Check(state, "CPU policy model is wired into drivers and tests",
          Contains(cmake, "src/vmx/cpu_policy_model.cpp") &&
              Contains(cmake, "tests/cpu_policy_model_test.cpp"));
    Check(state, "CPU policy model performs no physical register access",
          !Contains(source, "__cpuid") && !Contains(source, "__readmsr") &&
              !Contains(source, "__writemsr") && !Contains(source, "__vmx"));
}

void CheckInterruptContract(const fs::path& root, TestState& state) {
    const std::string header =
        Source(root, "src/include/knhv_interrupt.h", state);
    const std::string source =
        Source(root, "src/interrupt/interrupt_model.cpp", state);
    const std::string test =
        Source(root, "tests/interrupt_model_test.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "interrupt model exposes bounded events and decisions",
          Contains(header, "InterruptState") &&
              Contains(header, "PostedInterruptDescriptor") &&
              Contains(source, "SelectInterrupt"));
    Check(state, "interrupt model orders and gates pending injection",
          Contains(source, "Priority") && Contains(source, "IsBlocked") &&
              Contains(test, "priority") && Contains(test, "STI"));
    Check(state, "posted interrupts drain through the virtual event queue",
          Contains(source, "DrainPostedInterrupt") &&
              Contains(source, "kInterruptEventPosted") &&
              Contains(test, "posted interrupt"));
    Check(state, "interrupt model is wired into drivers and tests",
          Contains(cmake, "src/interrupt/interrupt_model.cpp") &&
              Contains(cmake, "tests/interrupt_model_test.cpp"));
    Check(state, "interrupt model does not access physical APIC state",
          !Contains(source, "MmMapIoSpace") &&
              !Contains(source, "__readmsr") && !Contains(source, "__vmx"));
}

void CheckVpidContract(const fs::path& root, TestState& state) {
    const std::string header = Source(root, "src/include/knhv_vpid.h", state);
    const std::string source = Source(root, "src/vmx/vpid_model.cpp", state);
    const std::string test = Source(root, "tests/vpid_model_test.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "VPID model exposes versioned lease and shootdown contracts",
          Contains(header, "VpidLease") &&
              Contains(header, "ShootdownRequest") &&
              Contains(header, "ReclaimVpid") &&
              Contains(source, "CompleteShootdown"));
    Check(state, "VPID reclaim requires a completed matching shootdown",
          Contains(source, "ShootdownCoversVpid") &&
              Contains(source, "ShootdownStateKind::Completed") &&
              Contains(test, "cannot be reclaimed"));
    Check(state, "VPID model gates all-context invalidation and timeouts",
          Contains(source, "kShootdownAllowAllContext") &&
              Contains(source, "TimedOut") &&
              Contains(test, "explicit opt-in") &&
              Contains(test, "marked timed out"));
    Check(state, "VPID model is wired into drivers and host tests",
          Contains(cmake, "src/vmx/vpid_model.cpp") &&
              Contains(cmake, "tests/vpid_model_test.cpp"));
    Check(state, "VPID model executes no physical invalidation instruction",
          !Contains(source, "__vmx") && !Contains(source, "__invvpid") &&
              !Contains(source, "__invept") && !Contains(source, "__writemsr"));
}

void CheckWhpContract(const fs::path& root, TestState& state) {
    const std::string header = Source(root, "src/include/knhv_whp.h", state);
    const std::string source = Source(root, "src/whp/whp_model.cpp", state);
    const std::string test = Source(root, "tests/whp_model_test.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    Check(state, "WHP model exposes capability, partition, and vCPU contracts",
          Contains(header, "WhpCapabilities") &&
              Contains(header, "WhpPartition") &&
              Contains(header, "WhpVcpu") &&
              Contains(source, "CreateWhpPartition"));
    Check(state, "WHP model requires capabilities before nested configuration",
          Contains(source, "kWhpCapNestedVmx") &&
              Contains(source, "kWhpPartitionEnableNestedVmx") &&
              Contains(test, "without capability"));
    Check(state, "WHP model routes exits and rejects stale generations",
          Contains(source, "EvaluateWhpExit") &&
              Contains(source, "GenerationMismatch") &&
              Contains(test, "routes CPUID") &&
              Contains(test, "stale generations"));
    Check(state, "WHP model is wired into drivers and host tests",
          Contains(cmake, "src/whp/whp_model.cpp") &&
              Contains(cmake, "tests/whp_model_test.cpp"));
    Check(state, "WHP model performs no direct VMX or device operations",
          !Contains(source, "WHvCreatePartition") &&
              !Contains(source, "WHvRunVirtualProcessor") &&
              !Contains(source, "__vmx") && !Contains(source, "__writemsr") &&
              !Contains(source, "DeviceIoControl"));
}

void CheckAbiV2Contract(const fs::path& root, TestState& state) {
    const std::string abi = Source(root, "src/include/knhv_abi.h", state);
    const std::string ioctl =
        Source(root, "src/include/knhv_control_ioctl.h", state);
    const std::string provider =
        Source(root, "src/include/knhv_provider.h", state);
    const std::string implementation =
        Source(root, "src/provider/provider_v2.cpp", state);
    const std::string control =
        Source(root, "src/control/control_device.cpp", state);
    const std::string cmake = Source(root, "CMakeLists.txt", state);
    const std::string probe =
        Source(root, "HV_PROBE_TESTER/nested_probe.cpp", state);
    Check(state, "ABI v2 exposes bounded capability and lease structures",
          Contains(abi, "kAbiV2Version") &&
              Contains(abi, "HvCapabilitySnapshotV2") &&
              Contains(abi, "HvOwnerLeaseV2") &&
              Contains(abi, "IsAbiV2BufferValid") &&
              Contains(abi, "kAbiV2MaxStructSize"));
    Check(state, "ABI v2 IOCTLs are explicitly versioned",
          Contains(ioctl, "IOCTL_KNHV_QUERY_CAPS_V2") &&
              Contains(ioctl, "IOCTL_KNHV_ACQUIRE_LEASE_V2") &&
              Contains(ioctl, "IOCTL_KNHV_RELEASE_LEASE_V2"));
    Check(state, "provider v2 selection is shared and fail-closed",
          Contains(provider, "SelectProviderV2") &&
              Contains(provider, "LeaseMatchesCapabilityV2") &&
              Contains(implementation, "RequiredFeaturesKnown") &&
              Contains(implementation, "HardwareOwnerConflict") &&
              Contains(implementation, "kLeaseFlagSynthetic") &&
              !Contains(implementation, "__vmx") &&
              !Contains(implementation, "__writemsr"));
    Check(state, "control v2 paths validate length and bind the file owner",
          Contains(cmake, "src/provider/provider_v2.cpp") &&
              Contains(control, "VersionedV2InputFits") &&
              Contains(control, "HandleAcquireLeaseV2") &&
              Contains(control, "HandleReleaseLeaseV2") &&
              Contains(control, "FindSession(extension, request.session,") &&
              Contains(control, "IOCTL_KNHV_QUERY_CAPS_V2"));
    Check(state, "nested probe exercises the v2 lease lifecycle",
          Contains(probe, "QueryCapsV2") &&
              Contains(probe, "AcquireSyntheticLease") &&
              Contains(probe, "ReleaseLeaseV2") &&
              Contains(probe, "IOCTL_KNHV_ACQUIRE_LEASE_V2"));
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
    CheckBenchmarkContract(root, state);
    CheckPreflightContract(root, state);
    CheckAbiV2Contract(root, state);
    CheckEptTimeContract(root, state);
    CheckVmcs02Contract(root, state);
    CheckIommuContract(root, state);
    CheckExitContract(root, state);
    CheckCpuPolicyContract(root, state);
    CheckVpidContract(root, state);
    CheckWhpContract(root, state);
    CheckInterruptContract(root, state);
    CheckPureModels(state);
    RunNestedModelContract(root, state);
}

}  // namespace knhv_tests
