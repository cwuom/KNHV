# KNHV

![IDE](https://img.shields.io/badge/IDE-VS%20Code%20%2B%20CMake-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Standard](https://img.shields.io/badge/Standard-C%2B%2B17-blue)
![Target](https://img.shields.io/badge/Target-Windows%2011%2025H2-green)

**KanoHypervisor** is a Windows x64 kernel driver for Intel VT-x research and bring-up.
It is intended for an isolated test installation with a kernel debugger.
Current status: research and bring-up; it is not a production hypervisor.

## Validation profile

The primary validation profile is an isolated reference target:

- Windows 11 25H2, x64
- Intel Core i7-14700KF
- a recovery snapshot and an attached kernel debugger
- no production, safety-critical, or personal-data workloads

Host-only contract tests can run on other supported Windows x64 systems. VMX,
service, and signature results must be collected on the isolated target.
The compile host is not a runtime validation target; building an artifact there
does not establish driver, HyperDbg, nested-VMX, passthrough, or performance
compatibility.

## Scope

- Intel VT-x late launch and VM-exit state handling
- fail-closed capability checks
- orderly multi-processor teardown with bounded retries
- quarantine when VMX ownership cannot be proven to be released
- versioned provider and session ABI for a future BootL0 interposer
- a pure software VMCS12/nested-VMX contract model
- an isolated `KNHV-NestedTest.sys` contract-test driver
- no physical BootL0 handoff, EPT/VMCS02 acceleration, device passthrough, or
  production support

## Repository layout

| Path | Responsibility |
| --- | --- |
| `src/core` | Driver entry, lifecycle facade, and shared runtime state |
| `src/vmx` | Feature gates, VMCS setup, launch, exits, diagnostics, and stop paths |
| `src/include` | Public, private, and logging contracts |
| `src/asm` | VMX entry, instruction wrappers, launch, and restore routines |
| `src/nested` | Pure VMCS12, VMX instruction, address, and exit model |
| `src/provider` | Capability-gated provider selection |
| `src/control` | Shared secure WDM control-device implementation |
| `src/test_driver` | Independent nested contract-test driver entry point |
| `drivers` | Separate INF packages for the two control services |
| `tests` | Source, ABI, artifact, and opt-in runtime checks |
| `tools` | Build, signing, certificate, and TESTSIGNING helpers |

The C++ and MASM frame layouts share `src/asm/vmx_asm.inc` and are guarded by
static assertions and contract tests. Change both sides together when editing
an offset or calling convention.

## Requirements

- Windows 11 25H2 x64 for the primary validation profile
- Visual Studio x64 C++ tools and MASM
- a Windows SDK and a matching Windows Driver Kit (WDK)
- CMake 3.23 or newer and Ninja

`ntifs.h` is provided by the WDK, not by the Windows SDK alone. Open the
repository from a Visual Studio Developer PowerShell. If more than one WDK is
installed, pass its root with `-WdkRoot` or `-DWDK_CONTENT_ROOT`.

To record the target before a hardware test, use these read-only commands:

```powershell
Get-CimInstance Win32_OperatingSystem |
  Select-Object Caption, Version, BuildNumber
Get-CimInstance Win32_Processor |
  Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors
```

## Configure and build

Run these commands from the repository root in a Developer PowerShell:

```powershell
$env:VSLANG = "1033"
cmake --preset vscode-debug
cmake --build --preset vscode-debug --parallel 4
```

For an optimized image:

```powershell
$env:VSLANG = "1033"
cmake --preset vscode-release
cmake --build --preset vscode-release --parallel 4
```

`VSLANG=1033` requests the MSVC message language where that resource is
installed; CMake also detects the compiler's `/showIncludes` prefix. It does
not change the language of the driver or the test binaries.

The output directory is `build/vscode/<Configuration>/`. Generated runtime
images are classified by kind, while linker PDB files stay in the
configuration root:

- `bin/KNHV_ContractTests.exe`
- `bin/KNHV_NestedProbe.exe`
- `bin/KNHV_NativeVmxProbe.exe`
- `bin/KNHV_NativeLikeBench.exe`
- `bin/KNHV_VmxExitBench.exe`
- `bin/KNHV_TscQpcBench.exe`
- `bin/KNHV_EptHookBench.exe`
- `bin/KNHV_DeviceIoBench.exe`
- `sys/KNHV.sys`
- `sys/KNHV-Control.sys`
- `sys/KNHV-NestedTest.sys`
- `KNHV*.pdb`

`CMakeFiles/` and `Testing/` remain CMake's internal build directories. The
native self-test source is `HV_PROBE_TESTER/native_vmx_probe.cpp`.

The two auxiliary SYS files expose only the versioned control contract. They do
not execute physical `VMXON`; the current `KNHV.sys` remains the native,
late-launch research baseline. A physical top-level KNHV L0 requires a
separately validated boot-time handoff and is outside the current release
profile.

`KNHV-NestedTest.sys` advertises a deliberately marked
`kFlagSyntheticSnapshot` so the host-only nested model can be exercised. That
flag is laboratory-only: it is not evidence of a BootL0 handoff, VMCS02/EPT
hardware, WHP integration, or transparent passthrough. The current control
contract keeps `VirtualizationReady=false` for that synthetic path while still
allowing the model IOCTLs to run. It also uses a bounded session table, a
generation key, and the creating file-object binding. It still does not verify
a production image manifest/signature or provide a production broker identity.
Do not deploy these auxiliary images as a production hypervisor or as a
security boundary.

The CMake Tools integration exports `compile_commands.json` with the project
headers and WDK `km` include directory. After changing the WDK or toolchain,
run `CMake: Delete Cache and Reconfigure`. If IntelliSense still reports a
missing `ntifs.h`, reset the C/C++ IntelliSense database and reopen the source
file under `src/vmx`.

## Tests

The default suite is host-only. It does not execute VMX instructions, load a
driver, change TESTSIGNING, or start a service:

```powershell
.\build\vscode\Debug\bin\KNHV_ContractTests.exe --root .
ctest --test-dir build\vscode\Debug --output-on-failure
```

The host-only suite includes provider-selection, BootL0 ownership-state, and
VMCS12/nested-instruction model tests. It does not load either auxiliary
driver, change TESTSIGNING, or execute VMX instructions.

After the signed `KNHV-NestedTest.sys` test driver is running on an isolated
x64 Windows target, the dedicated probe can validate its public synthetic
nested-model device contract:

```powershell
.\build\vscode\Release\bin\KNHV_NestedProbe.exe --caps-only
.\build\vscode\Release\bin\KNHV_NestedProbe.exe
```

The full probe opens `\\.\KNHVNestedTest`, registers the known laboratory
provider, and exercises VMXON, VMCS12 setup, VMLAUNCH, reflected L2 exits,
VMRESUME, VMXOFF, and session release. It does not execute physical VMX
instructions or verify a physical BootL0/VMCS02/EPT02 implementation.

On an isolated target where `KNHV.sys` is already running, the native VMX
self-test is available as:

```powershell
.\build\vscode\Release\bin\KNHV_NativeVmxProbe.exe
```

The native probe must not be used as a nested or coexistence test. It checks
only the existing KNHV VM-exit path and is intentionally separate from the
synthetic nested-model probe.

The benchmark executables are host-only diagnostic tools. They use the common
`knhv-bench-1` JSON schema; a `.csv` output contains sample columns only. The
five tools cover native-like CPU and memory work, TSC/QPC clock sampling,
synthetic VM-exit accounting, synthetic EPT-hook accounting, and a virtual
device-I/O queue. They do not execute physical VMX instructions, access PCI
devices, or enable DMA.

For a local baseline, write results to a directory owned by the caller:

```powershell
.\build\vscode\Release\bin\KNHV_NativeLikeBench.exe `
  --mode baseline --workload cpu,mem --duration-ms 1000 --repeat 3 `
  --out results\native_like.json
```

`tools/Run-Benchmarks.ps1` runs the host-only suite and records commands,
provenance, hashes, and result files in the output directory supplied by the
caller. The `native-l0` and `nested-l1` modes are capability-gated and fail
closed when a verified provider, owner, or nested capability is unavailable.
The device-I/O tool accepts only its explicit virtual profile; it never
detaches, resets, or transfers data to a physical device. Comparison mode
requires matching workload, scope, configuration, and host provenance before
reporting a result.

To validate a built SYS and its matching PDB:

```powershell
.\build\vscode\Debug\bin\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\Debug\sys\KNHV.sys
```

The following checks are explicit opt-ins and belong only on the isolated
Windows 11 25H2 / i7-14700KF target:

```powershell
.\build\vscode\Debug\bin\KNHV_ContractTests.exe --root . --hardware

.\build\vscode\Debug\bin\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\Debug\sys\KNHV.sys `
  --signature `
  --allow-test-root

.\build\vscode\Debug\bin\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\Debug\sys\KNHV.sys `
  --runtime --start --stop
```

`--signature` expects a test-signed image. `--runtime` requires a prepared
service, a kernel debugger, and a recovery path. The test only stops a service
that it started itself.

## Deterministic fault injection

Fault injection is disabled in normal builds. Use a separate build directory
to validate a launch-rollback configuration:

```powershell
$env:VSLANG = "1033"
cmake -S . -B build\vscode\FaultDebug -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug `
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
  -DWDK_WINVER=0x0A00 `
  -DKNHV_BUILD_TESTS=ON `
  -DKNHV_FAULT_INJECTION=ON `
  -DKNHV_TEST_FAIL_CPU=0 `
  -DKNHV_TEST_FAIL_STAGE=8 `
  -DKNHV_ARTIFACT_ROOT=build\vscode\FaultDebug
cmake --build build\vscode\FaultDebug --parallel 4
.\build\vscode\FaultDebug\bin\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\FaultDebug\sys\KNHV.sys
```

This command validates the fault-injection build and its artifact contract; it
does not load the driver or trigger a VMX launch.

`KNHV_TEST_FAIL_CPU` selects the logical processor and
`KNHV_TEST_FAIL_STAGE` selects a bounded stage. These hooks request a
controlled rollback; they do not emulate arbitrary hardware failures. To
exercise one, sign and register this separate SYS only on the isolated target,
attach KD, and retain the rollback log. The normal `--runtime --start --stop`
check expects a successful launch, so it is not the expected-result check for
an intentionally injected launch failure.

## Tool scripts

All scripts are intended to be run from the repository root. They use the
installed Visual Studio and WDK rather than hard-coded compiler paths.

| Script | Purpose | State changes |
| --- | --- | --- |
| `tools/Build-Driver.ps1` | Discover VS/WDK, configure, and build unsigned SYS/EXE/PDB artifacts | Writes only the selected build directory using `sys/`, `bin/`, and the root for linker PDBs |
| `tools/Build-And-Sign-Driver.ps1` | Build, create or reuse a local test certificate, then sign the SYS | Writes `certs/`, may install test certificates, and changes the SYS |
| `tools/Generate-Test-Certificate.ps1` | Create a private Root CA and kernel-code-signing leaf certificate | Writes `certs/` and may update certificate stores |
| `tools/Sign-Driver.ps1` | Sign an existing SYS and verify Authenticode plus kernel policy | Changes the specified SYS; requires `signtool.exe` and a certificate |
| `tools/Set-TestSigning.ps1` | Read or change Windows TESTSIGNING state | `-Status` is read-only; `-Enable` and `-Disable` change BCD and require a reboot |
| `tools/Run-Benchmarks.ps1` | Run the host-only benchmark suite and write a reproducibility manifest | Writes only the caller-selected output directory |

### Build helper

```powershell
.\tools\Build-Driver.ps1 -Configuration Debug
.\tools\Build-Driver.ps1 -Configuration Release
.\tools\Build-Driver.ps1 -Configuration Debug -ConfigureOnly
```

Use `-WdkRoot 'C:\Program Files (x86)\Windows Kits\10'` when automatic WDK
selection is not appropriate.

The legacy standalone probe entry point remains available from an x64 Native
Tools Command Prompt:

```bat
cd HV_PROBE_TESTER
build_msvc.bat
```

It writes `build\standalone\bin\KNHV_NativeVmxProbe.exe` and its PDB instead
of placing a binary beside the source file.

### Test certificate and signing

Signing is never enabled by the CMake presets. For an isolated test target:

```powershell
.\tools\Build-And-Sign-Driver.ps1 -Configuration Debug
```

The generated private key and password stay under the ignored `certs/`
directory. Do not commit them. `-Recreate` on
`Generate-Test-Certificate.ps1` replaces the local test chain and should only
be used when the existing chain is intentionally being retired.

For an existing certificate and SYS, the lower-level command is:

```powershell
.\tools\Sign-Driver.ps1 `
  -DriverPath .\build\vscode\Debug\sys\KNHV.sys `
  -Certificate .\certs\KNHV_test.pfx `
  -Password '<test-password>' `
  -AllowUntrustedTestCertificate
```

Do not put a real password in source control or shell history. A production
release needs the platform's approved kernel-code-signing process; a private
test root is not production trust.

### TESTSIGNING

```powershell
.\tools\Set-TestSigning.ps1 -Status
```

Only on the isolated test installation, from an elevated PowerShell:

```powershell
.\tools\Set-TestSigning.ps1 -Enable
# reboot before loading a test-signed driver
.\tools\Set-TestSigning.ps1 -Disable
# reboot again after disabling test mode
```

Secure Boot, enterprise policy, or firmware settings may reject TESTSIGNING.
Do not change it on a production machine.


## Acknowledgements

The implementation was informed by the Intel Software Developer's Manual and
public research projects such as [HyperDbg](https://github.com/HyperDbg/HyperDbg).

## License

MIT License. See [LICENSE](LICENSE).
