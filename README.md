# KNHV

![IDE](https://img.shields.io/badge/IDE-VS%20Code%20%2B%20CMake-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Standard](https://img.shields.io/badge/Standard-C%2B%2B17-blue)
![Target](https://img.shields.io/badge/Target-Windows%2011%2025H2-green)

**KanoHypervisor** is a Windows x64 kernel driver for Intel VT-x research and bring-up.
It is intended for an isolated test installation with a kernel debugger.

## Validation profile

The primary validation target for this release is:

- Windows 11 25H2, x64
- Intel Core i7-14700KF
- a recovery snapshot and an attached kernel debugger
- no production, safety-critical, or personal-data workloads

Host-only contract tests can run on other supported Windows x64 systems. VMX,
service, and signature results must be collected on the isolated target.

## Scope

- Intel VT-x late launch and VM-exit state handling
- fail-closed capability checks
- orderly multi-processor teardown with bounded retries
- quarantine when VMX ownership cannot be proven to be released
- no EPT, nested virtualization, device passthrough, or production support

## Repository layout

| Path | Responsibility |
| --- | --- |
| `src/core` | Driver entry, lifecycle facade, and shared runtime state |
| `src/vmx` | Feature gates, VMCS setup, launch, exits, diagnostics, and stop paths |
| `src/include` | Public, private, and logging contracts |
| `src/asm` | VMX entry, instruction wrappers, launch, and restore routines |
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

The output directory is `build/vscode/<Configuration>/` and contains:

- `KNHV.sys`
- `KNHV.pdb`
- `KNHV_ContractTests.exe`

The CMake Tools integration exports `compile_commands.json` with the project
headers and WDK `km` include directory. After changing the WDK or toolchain,
run `CMake: Delete Cache and Reconfigure`. If IntelliSense still reports a
missing `ntifs.h`, reset the C/C++ IntelliSense database and reopen the source
file under `src/vmx`.

## Tests

The default suite is host-only. It does not execute VMX instructions, load a
driver, change TESTSIGNING, or start a service:

```powershell
.\build\vscode\Debug\KNHV_ContractTests.exe --root .
ctest --test-dir build\vscode\Debug --output-on-failure
```

To validate a built SYS and its matching PDB:

```powershell
.\build\vscode\Debug\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\Debug\KNHV.sys
```

The following checks are explicit opt-ins and belong only on the isolated
Windows 11 25H2 / i7-14700KF target:

```powershell
.\build\vscode\Debug\KNHV_ContractTests.exe --root . --hardware

.\build\vscode\Debug\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\Debug\KNHV.sys `
  --signature `
  --allow-test-root

.\build\vscode\Debug\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\Debug\KNHV.sys `
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
  -DKNHV_TEST_FAIL_STAGE=8
cmake --build build\vscode\FaultDebug --parallel 4
.\build\vscode\FaultDebug\KNHV_ContractTests.exe `
  --root . `
  --driver .\build\vscode\FaultDebug\KNHV.sys
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
| `tools/Build-Driver.ps1` | Discover VS/WDK, configure, and build an unsigned SYS/PDB | Writes only the selected build directory |
| `tools/Build-And-Sign-Driver.ps1` | Build, create or reuse a local test certificate, then sign the SYS | Writes `certs/`, may install test certificates, and changes the SYS |
| `tools/Generate-Test-Certificate.ps1` | Create a private Root CA and kernel-code-signing leaf certificate | Writes `certs/` and may update certificate stores |
| `tools/Sign-Driver.ps1` | Sign an existing SYS and verify Authenticode plus kernel policy | Changes the specified SYS; requires `signtool.exe` and a certificate |
| `tools/Set-TestSigning.ps1` | Read or change Windows TESTSIGNING state | `-Status` is read-only; `-Enable` and `-Disable` change BCD and require a reboot |

### Build helper

```powershell
.\tools\Build-Driver.ps1 -Configuration Debug
.\tools\Build-Driver.ps1 -Configuration Release
.\tools\Build-Driver.ps1 -Configuration Debug -ConfigureOnly
```

Use `-WdkRoot 'C:\Program Files (x86)\Windows Kits\10'` when automatic WDK
selection is not appropriate.

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
  -DriverPath .\build\vscode\Debug\KNHV.sys `
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
