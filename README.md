# Nested-HV

![IDE](https://img.shields.io/badge/IDE-VS%20Code%20%2B%20CMake-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Standard](https://img.shields.io/badge/Standard-C%2B%2B17-blue)
![Target](https://img.shields.io/badge/Target-Windows%2011%2025H2-green)

**Nested-HV** is a minimalistic Type-2 Hypervisor (Blue Pill) implementation for Intel Processors based on VT-x technology.

Designed for research and educational purposes, it transitions the running operating system into a virtual machine on the fly. Hardware/OS combinations must be validated in an isolated test environment before use; this repository does not claim universal stability or production compatibility.

## Features

* **Blue Pill Architecture**: Seamlessly transitions the OS into a VM without rebooting.
* **Compatibility checks**: Refuses to start when required VMX controls are unavailable; test only on supported Intel VT-x systems.
* **State Transparency**: Preserves full GPR and Extended State (XSave/XRstor).
* **Modern Toolchain**: Built using **VS Code**, **CMake**, and **Ninja** with MSVC.

The VMX setup is deliberately conservative: it refuses VM-entry when the CPU
forces an execution/interrupt control that this non-nested monitor does not
emulate, and it never attempts to recover from a VMRESUME/invalid-guest-state
failure by guessing a return frame.  Such a fatal path parks the affected
logical processor after VMXOFF; this is safer than escalating into a reset, but
it still requires kernel-debugger validation on the target machine.  If a CPU
is parked, unloading is intentionally blocked because that processor is still
executing code in this image; reboot the test machine (or recover it with a
kernel debugger) instead of forcing driver removal.

## Scope

Nested virtualization and EPT are intentionally out of scope for this build. The
driver is intended for controlled research and should never be installed on a
production or safety-critical system.

## Loading and testing

Do not use undocumented manual mappers for routine validation. Use a properly
installed, test-signed driver in an isolated VM with a kernel debugger attached;
keep a recovery snapshot and enable test-signing only for that VM. The VS Code
task **Enable Windows TESTSIGNING (reboot required)** runs the supported
`bcdedit` command and does not reboot the machine automatically. Reboot after
changing the setting, then use **Windows TESTSIGNING status** to confirm it.
On a normal run the driver can be unloaded through its regular stop path. If
the driver reports a parked processor, do not force-unload it; reboot the test
environment after collecting the debugger log.

If `sc start Nested_HV` returns error 50 (`STATUS_NOT_SUPPORTED`,
`0xC00000BB`), inspect the KD output for `[HV] VMX gate rejected:`. The driver
fails closed when Hyper-V/another hypervisor is active, VMX is disabled by
firmware or `IA32_FEATURE_CONTROL`, or the host XSAVE/CET state is outside the
implemented scope. Do not remove this gate to force a start; disable the
conflicting type-1 hypervisor only on an isolated bare-metal test machine, then
reboot and try again. A line naming `NetworkPrivacyPolicy` is a separate
Microsoft system driver and is not evidence that `Nested_HV` failed.

## Build Instructions (VS Code)

### Prerequisites
* **VS Code** with the CMake Tools and C/C++ extensions.
* **Visual Studio 2022** (C++ Desktop Development workload).
* **Windows Driver Kit (WDK)** matching the Windows SDK build number. For
  Windows 11 25H2 with Visual Studio 2022, use the **10.0.26100.x** WDK
  family; Visual Studio 2026 uses the **10.0.28000.x** family.
* **Windows SDK** (provides `signtool.exe` when signing is required).

`ntddk.h` is supplied by the WDK, not by the Windows SDK. Its normal location
is `C:\Program Files (x86)\Windows Kits\10\Include\<version>\km\ntddk.h`. If VS Code shows
`cannot open source file "ntddk.h"`, install the WDK matching the installed
SDK, then reopen VS Code from a Visual Studio Developer PowerShell. The
checked-in C/C++ configuration searches both the standard Windows Kits root
(`wdkRoot`) and the `WDKContentRoot` environment variable, so a kit installed
on another drive can be selected by setting `WDKContentRoot` before launching
VS Code. The build helper accepts `-WdkRoot <path>`, checks for `ntddk.h`
before invoking CMake, and prints the searched paths when the WDK is absent.

Microsoft's supported-version guidance requires the SDK and WDK build numbers
to match. Installing only the SDK creates `um`, `shared`, and `ucrt` directories
but not the `km` directory or `ntddk.h`.

### Configuration
1. Clone the repository and open the folder in VS Code.
2. Start a Visual Studio Developer PowerShell, or let `tools/Build-Driver.ps1` discover
   the Visual Studio toolchain automatically.
3. Run **Build Driver (unsigned)** from the Command Palette. The WDK is selected
   automatically. For the PowerShell helper, pass `-WdkRoot <path>` when more
   than one kit is installed; for direct CMake use, pass
   `-DWDK_CONTENT_ROOT=<path>`.

The checked-in `CMakePresets.json` also exposes `vscode-debug` and
`vscode-release` presets for the CMake Tools extension and command-line builds.

### Compilation
The output driver `Nested_HV.sys` is generated in
`build/vscode/<Configuration>`. The default CMake option is
`NESTED_HV_SIGN=OFF`, so a missing certificate never breaks a normal build.

For a direct SYS build in VS Code, run `Terminal > Run Build Task` and choose
`Build SYS + PDB (Debug)` or `Build SYS + PDB (Release)`. The equivalent
CMake preset commands are:

```powershell
cmake --preset sys-debug
cmake --build --preset sys-debug
```

The WDK target is named `Nested_HV`; because `wdk_add_driver` sets the target
suffix, its artifact is `Nested_HV.sys`, not an executable `.exe`. The VS Code
`launch.json` entries use the built-in `node-terminal` runner only to invoke
the build scripts; they do not start a Kernel Debugger. They emit both
`Nested_HV.sys` and its matching `Nested_HV.pdb`.

### C++ driver tests

The repository includes the independent user-mode C++ target
`Nested_HV_ContractTests`. It does not include `ntddk.h`, execute `VMXON`, or
modify the current machine by default. It checks the Intel VMCS encodings, the
fixed MASM/`GuestContext` offsets, paired CET controls, XSAVES/XRSTORS
fail-closed paths, and (when an artifact is supplied) the SYS PE image and
matching PDB. This follows the control-program pattern used by open-source
VT-x projects such as hvpp: the normal test binary is safe, while service
start is an explicit operation on an isolated target.

```powershell
cmake --preset sys-debug
cmake --build --preset sys-debug
.\build\vscode\Debug\Nested_HV_ContractTests.exe --root .
.\build\vscode\Debug\Nested_HV_ContractTests.exe --root . --hardware
```

`--signature --driver <path> --allow-test-root` validates the embedded
Authenticode signature while allowing the expected untrusted private test root.
`--runtime --start` is intentionally opt-in and must only be used with KD and
a recovery snapshot on a dedicated test machine. After the service reaches
`RUNNING`, it executes the driver's reserved magic `CPUID` leaf as an
end-to-end VM-exit smoke test; `--stop` only stops a service that this process
started.

## Driver signing

The Run and Debug entries **Build and Sign SYS (Debug/Release)** and the tasks
**Build and Sign SYS (..., auto test certificate)** generate a private Root CA
and a leaf test-signing certificate automatically under `certs/`, then sign
the SYS with the leaf. The leaf contains both the Authenticode Code Signing
EKU and the Windows Kernel Mode Code Signing EKU. No path or password input is
required. The certificate password is kept in an ignored local `.pwd` file.
When elevated, the generator installs the root and publisher certificates in
the machine stores; restricted stores are reported as warnings rather than
making the build fail. The task discovers `signtool.exe` from the active
Windows SDK (or `SIGNTOOL_PATH`). It verifies the embedded signature and
reports `/kp` separately: a private test chain may be rejected because it does
not chain to a Microsoft root, even though it is correctly test-signed.
For a reproducible build with your own certificate, pass the certificate
settings to CMake:

```powershell
cmake -S . -B build\signed -G Ninja `
  -DNESTED_HV_SIGN=ON `
  -DNESTED_HV_SIGNTOOL="$env:WindowsSdkDir\bin\$env:WindowsSDKVersion\x64\signtool.exe" `
  -DNESTED_HV_SIGN_CERT="C:\certs\Nested_HV_test.pfx"
cmake --build build\signed
```

Never commit private keys or passwords. A production kernel driver also needs a
Microsoft-attested/WHQL signing path; a local test certificate is intended only
for test-signing on an isolated machine.

## License

MIT License.
