# KNHV

![IDE](https://img.shields.io/badge/IDE-VS%20Code%20%2B%20CMake-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Standard](https://img.shields.io/badge/Standard-C%2B%2B17-blue)
![Target](https://img.shields.io/badge/Target-Windows%2011%2025H2-green)

**Kano-HV** is a minimalistic Type-2 Hypervisor (Blue Pill) implementation for Intel Processors based on VT-x technology.

Designed for research and educational purposes, it transitions the running operating system into a virtual machine on the fly. Hardware/OS combinations must be validated in an isolated test environment before use; this repository does not claim universal stability or production compatibility.

## Features

* **Blue Pill Architecture**: Seamlessly transitions the OS into a VM without rebooting.
* **Compatibility checks**: Refuses to start when required VMX controls or state-preservation capabilities are unavailable; nested virtualization is intentionally disabled.
* **All-core production mode**: Launches the validated contract on every participating logical processor by default while keeping one coordinator processor native for the late-load debugger rendezvous; the single-CPU switch is reserved for explicit bring-up builds.
* **Generation-aware VMX contract**: Selects legacy/true controls and the available secondary, tertiary, XSAVES, CET, RDTSCP, and INVPCID capabilities per processor. The save-frame and CET transition contracts remain global, while optional VMX controls are selected independently on each processor.
* **State Transparency**: Preserves full GPR and Extended State (XSave/XRstor).
* **Modern Toolchain**: Built using **VS Code**, **CMake**, and **Ninja** with MSVC.

The VMX setup is deliberately conservative: it refuses VM-entry when the CPU forces an execution/interrupt control that this non-nested monitor does not emulate, and it never attempts to recover from a VMRESUME/invalid-guest-state failure by guessing a return frame. A VMRESUME failure first validates the saved native context. If the frame is not provably safe, the driver restores the host XCR0/XSS/KERNEL_GS_BASE snapshot and raises the dedicated bugcheck `0x200`; its parameters contain the CPU, saved VM-exit reason, guest RIP, and guest RSP. This intentionally stops the machine while the original fault is still visible in KD instead of waiting for a watchdog timeout. If a callback ever cannot prove that every processor left VMX, unload is quarantined and the driver image and VMX allocations remain resident; reboot the isolated test machine or recover it with KD rather than forcing removal.

The exit frame supports ordinary XSAVE on legacy Intel processors. On newer Windows 11 systems, XSAVES is enabled only when CPUID.(D,1), the VMX secondary control, the XSS mask, and the reported compacted area all agree. The host IA32_XSS mask is kept separately from the guest mask. The host frame can preserve the CET_U component when Windows has selected it, but this build does not expose CET capabilities or CET_U XSTATE to the guest until the complete user and supervisor CET MSR contract is implemented. Intel PT remains host-only: its CPUID leaves are hidden and its RTIT MSR window is intercepted. Active user or supervisor CET, Intel PT, supervisor shadow stacks, and a non-zero interrupt SSP table are rejected before VMXON because this build does not virtualize those controls completely. The common Windows 11 25H2 state `CR4.CET=1`, `IA32_XSS=0x900`, `S_CET=0`, and zero SSP values is accepted only when the paired VMX CET entry/exit controls are available.

Guest-visible optional instructions are the intersection of the capabilities validated on every participating logical processor, so RDTSCP and INVPCID are hidden when a single P/E core cannot safely pass them through. FRED and LKGS remain hidden, and guest writes that attempt to enable `CR4.FRED` are rejected because this build retains the legacy VM-exit event-delivery contract.

The MASM `VMWRITE` wrapper strictly follows architectural register encoding rules: `HvVmWrite(Field, Value)` receives `RCX=Field` and `RDX=Value`; VMWRITE's first operand is the value and its second register operand is the field. The wrapper therefore uses `vmwrite rdx, rcx` (encoding `0F 79 D1`). `VMREAD` remains `vmread destination, field`; the contract test checks both source forms and the operand encoding so a swapped wrapper cannot silently reach VMX hardware.

The debugger log is staged by contract and processor. `[HV] XSTATE contract` and `[HV] VMX control contract` describe the feature gate and selected generation profile, `CPU <n> VMCS` records per-processor VMX setup and launch values, and the first 16 VM-exits per processor include reason, RIP, RSP, qualification, and flags. Fatal or unsupported exits print the guest CR3/CR4; only a context that passes the native teardown checks is resumed. The descriptor contract is refreshed at the authenticated unload boundary rather than on every ordinary exit, matching the low-overhead hot path, while an initial VM-entry masks `RFLAGS.IF` until the isolated launch thunk has left its private frame; the original flag is then restored with an `STI` interrupt shadow. This prevents a late-load interrupt from overwriting the saved return frame. If `VM_EXIT_IDT_VECTORING_INFO` reports an in-flight event, the monitor keeps the event snapshot and enters the same fail-stop diagnostic path instead of silently clearing it and issuing `VMRESUME`; event reinjection and interrupt-window queues are intentionally not claimed by this build.

## Scope

Nested virtualization and EPT are intentionally out of scope for this build. The driver is intended for controlled research and should never be installed on a production or safety-critical system.

## Loading and testing

Do not use undocumented manual mappers for routine validation. Use a properly installed, test-signed driver in an isolated VM with a kernel debugger attached; keep a recovery snapshot and enable test-signing only for that VM. The VS Code task **Enable Windows TESTSIGNING (reboot required)** runs the supported `bcdedit` command and does not reboot the machine automatically. Reboot after changing the setting, then use **Windows TESTSIGNING status** to confirm it. On a normal run the driver can be unloaded through its regular stop path. If the driver reports a parked processor, do not force-unload it; reboot the test environment after collecting the debugger log.

If `sc start Nested_HV` returns error 50 (`STATUS_NOT_SUPPORTED`, `0xC00000BB`), inspect the KD output for `[HV] VMX gate rejected:`. The driver fails closed when Hyper-V/another hypervisor is active, VMX is disabled by firmware or `IA32_FEATURE_CONTROL`, or the host XSAVE/CET state is outside the implemented scope. Do not remove this gate to force a start; disable the conflicting type-1 hypervisor only on an isolated bare-metal test machine, then reboot and try again. A line naming `NetworkPrivacyPolicy` is a separate Microsoft system driver and is not evidence that `Nested_HV` failed.

## Build Instructions (VS Code)

### Prerequisites
* **VS Code** with the CMake Tools and C/C++ extensions.
* **Visual Studio 2022** (C++ Desktop Development workload).
* **Windows Driver Kit (WDK)** matching the Windows SDK build number. For Windows 11 25H2 with Visual Studio 2022, use the **10.0.26100.x** WDK family; Visual Studio 2026 uses the **10.0.28000.x** family.
* **Windows SDK** (provides `signtool.exe` when signing is required).

`ntddk.h` is supplied by the WDK, not by the Windows SDK. Its normal location is `C:\Program Files (x86)\Windows Kits\10\Include\<version>\km\ntddk.h`. If VS Code shows `cannot open source file "ntddk.h"`, install the WDK matching the installed SDK, then reopen VS Code from a Visual Studio Developer PowerShell. The checked-in C/C++ configuration searches both the standard Windows Kits root (`wdkRoot`) and the `WDKContentRoot` environment variable, so a kit installed on another drive can be selected by setting `WDKContentRoot` before launching VS Code. The build helper accepts `-WdkRoot <path>`, checks for `ntddk.h` before invoking CMake, and prints the searched paths when the WDK is absent.

Microsoft's supported-version guidance requires the SDK and WDK build numbers to match. Installing only the SDK creates `um`, `shared`, and `ucrt` directories but not the `km` directory or `ntddk.h`.

### Configuration
1. Clone the repository and open the folder in VS Code.
2. Start a Visual Studio Developer PowerShell, or let `tools/Build-Driver.ps1` discover the Visual Studio toolchain automatically.
3. Run **Build Driver (unsigned)** from the Command Palette. The WDK is selected automatically. For the PowerShell helper, pass `-WdkRoot <path>` when more than one kit is installed; for direct CMake use, pass `-DWDK_CONTENT_ROOT=<path>`.

The checked-in `CMakePresets.json` also exposes `vscode-debug` and `vscode-release` presets for the CMake Tools extension and command-line builds.

The checked-in VS Code workspace uses CMake Tools' preset mode by default (`cmake.useCMakePresets: always`) with `vscode-debug` selected as both the configure and build preset. This keeps an active preset available for CMake Tools commands and avoids the `No configure preset is active` error. To use a Release build, select `vscode-release` as both presets before reconfiguring. The same `CMakePresets.json` remains available for command-line builds.

The workspace enables CMake Tools' compile-command export and asks the extension to copy the generated database to the repository root after a successful configure. If the C/C++ extension still reports missing compilation information, run **CMake: Delete Cache and Reconfigure** once, then select the `Nested_HV` configuration provider in the C/C++ status bar.

### Compilation
The output driver `Nested_HV.sys` is generated in `build/vscode/<Configuration>`. The default CMake option is `NESTED_HV_SIGN=OFF`, so a missing certificate never breaks a normal build.

For a direct SYS build in VS Code, run `Terminal > Run Build Task` and choose `Build SYS + PDB (Debug)` or `Build SYS + PDB (Release)`. The equivalent CMake preset commands are:

```powershell
cmake --preset sys-debug
cmake --build --preset sys-debug

```

The WDK target is named `Nested_HV`; because `wdk_add_driver` sets the target suffix, its artifact is `Nested_HV.sys`, not an executable `.exe`. The VS Code `launch.json` entries use the built-in `node-terminal` runner only to invoke the build scripts; they do not start a Kernel Debugger. They emit both `Nested_HV.sys` and its matching `Nested_HV.pdb`.

### C++ driver tests

The repository includes the independent user-mode C++ target `Nested_HV_ContractTests`. It does not include `ntddk.h`, execute `VMXON`, or modify the current machine by default. It checks the Intel VMCS encodings, the fixed MASM/`GuestContext` offsets, paired CET controls, XSAVES/XRSTORS fail-closed paths, and (when an artifact is supplied) the SYS PE image and matching PDB. This follows the control-program pattern used by open-source VT-x projects: the normal test binary is safe, while service start is an explicit operation on an isolated target.

```powershell
cmake --preset sys-debug
cmake --build --preset sys-debug
.\build\vscode\Debug\Nested_HV_ContractTests.exe --root .
.\build\vscode\Debug\Nested_HV_ContractTests.exe --root . --hardware

```

The hardware check accepts either the legacy FXSAVE backend or the XSAVE backend. XSAVES is reported as an optional capability, not a universal requirement.

`--signature --driver <path> --allow-test-root` validates the embedded Authenticode signature while allowing the expected untrusted private test root. `--runtime --start` is intentionally opt-in and must only be used with KD and a recovery snapshot on a dedicated test machine. After the service reaches `RUNNING`, it executes the driver's reserved magic `CPUID` leaf as an end-to-end VM-exit smoke test; `--stop` only stops a service that this process started.

For isolated rollback testing, enable the deterministic fault hooks at configure time. `HV_TEST_FAIL_CPU` selects the logical processor and `HV_TEST_FAIL_STAGE` selects a stage from `HvFaultStage` in `src/vmm.cpp`:

```powershell
cmake --preset vscode-debug `
  -DNESTED_HV_FAULT_INJECTION=ON `
  -DHV_TEST_FAIL_CPU=19 `
  -DHV_TEST_FAIL_STAGE=8
cmake --build --preset vscode-debug

```

The hooks request a controlled abort or rollback; they do not emulate a hardware VM-entry failure. Run them only on an isolated target with KD and a recovery path.

## Driver signing

The Run and Debug entries **Build and Sign SYS (Debug/Release)** and the tasks **Build and Sign SYS (..., auto test certificate)** generate a private Root CA and a leaf test-signing certificate automatically under `certs/`, then sign the SYS with the leaf. The leaf contains both the Authenticode Code Signing EKU and the Windows Kernel Mode Code Signing EKU. No path or password input is required. The certificate password is kept in an ignored local `.pwd` file. When elevated, the generator installs the root and publisher certificates in the machine stores; restricted stores are reported as warnings rather than making the build fail. The task discovers `signtool.exe` from the active Windows SDK (or `SIGNTOOL_PATH`). It verifies the embedded signature and reports `/kp` separately: a private test chain may be rejected because it does not chain to a Microsoft root, even though it is correctly test-signed. For a reproducible build with your own certificate, pass the certificate settings to CMake:

```powershell
cmake -S . -B build\signed -G Ninja `
  -DNESTED_HV_SIGN=ON `
  -DNESTED_HV_SIGNTOOL="$env:WindowsSdkDir\bin\$env:WindowsSDKVersion\x64\signtool.exe" `
  -DNESTED_HV_SIGN_CERT="C:\certs\Nested_HV_test.pfx"
cmake --build build\signed

```

Never commit private keys or passwords. A production kernel driver also needs a Microsoft-attested/WHQL signing path; a local test certificate is intended only for test-signing on an isolated machine.

## Acknowledgments

This project has been inspired by and references architectural designs from the open-source virtualization community. Special thanks to:

* **[HyperDbg](https://github.com/HyperDbg/HyperDbg)**: For pioneering modern VT-x debugger architectures, low-overhead VM-exit handlers, and robust kernel-level VMX transition paradigms.

## License

MIT License.
