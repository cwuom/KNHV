[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory,
    [ValidateRange(1, 3600000)]
    [uint64]$DurationMs = 1000,
    [ValidateRange(1, 1000)]
    [uint32]$Repeat = 3,
    [switch]$SkipNativeGate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$binDirectory = Join-Path $repoRoot ("build\vscode\{0}\bin" -f $Configuration)
if (-not (Test-Path -LiteralPath $binDirectory -PathType Container)) {
    throw "Benchmark directory does not exist: $binDirectory"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDirectory = Join-Path $repoRoot (".report\execution\run-{0}-{1}" -f $stamp, $Configuration.ToLowerInvariant())
} elseif (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

$seed = "1263421526"
$records = New-Object System.Collections.Generic.List[object]

function Convert-ToArgumentText([string[]]$Arguments) {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            $parts.Add('"' + $argument.Replace('"', '\"') + '"')
        } else {
            $parts.Add($argument)
        }
    }
    return ($parts -join ' ')
}

function Invoke-Benchmark(
    [string]$Key,
    [string]$ExecutableName,
    [string[]]$Arguments,
    [int[]]$ExpectedExitCodes
) {
    $executablePath = Join-Path $binDirectory $ExecutableName
    if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
        throw "Benchmark executable does not exist: $executablePath"
    }
    $jsonPath = $null
    for ($index = 0; $index -lt $Arguments.Count - 1; ++$index) {
        if ($Arguments[$index] -eq "--out") {
            $jsonPath = $Arguments[$index + 1]
            break
        }
    }
    $stdoutPath = Join-Path $OutputDirectory ($Key + ".stdout.txt")
    $stderrPath = Join-Path $OutputDirectory ($Key + ".stderr.txt")
    & $executablePath @Arguments 1> $stdoutPath 2> $stderrPath
    $exitCode = $LASTEXITCODE
    $parsed = $null
    if ($null -ne $jsonPath -and (Test-Path -LiteralPath $jsonPath -PathType Leaf) -and
        ([IO.Path]::GetExtension($jsonPath) -ieq ".json")) {
        try {
            $parsed = Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8 |
                ConvertFrom-Json
        } catch {
            $parsed = $null
        }
    }
    $expected = $ExpectedExitCodes -contains $exitCode
    $record = [ordered]@{
        key = $Key
        executable = (Resolve-Path -LiteralPath $executablePath).Path
        executable_sha256 = (Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash
        command = ((Resolve-Path -LiteralPath $executablePath).Path + " " +
                   (Convert-ToArgumentText $Arguments))
        exit_code = $exitCode
        expected_exit_code = $expected
        stdout = $stdoutPath
        stderr = $stderrPath
        result = if ($null -eq $parsed) {
            $null
        } else {
            [ordered]@{
                mode = $parsed.mode
                status = $parsed.status
                verdict = $parsed.verdict
                execution_scope = $parsed.execution_scope
                samples = $parsed.samples.count
                source_dirty = $parsed.build.source_dirty
                physical_dma_enabled = $parsed.physical_dma_enabled
                clock_backwards = $parsed.clock.backwards
                reason = $parsed.reason
            }
        }
    }
    $records.Add($record)
    if (-not $expected) {
        throw ("{0} returned unexpected exit code {1}" -f $Key, $exitCode)
    }
    return $record
}

function OutputPath([string]$Name) {
    return Join-Path $OutputDirectory $Name
}

$common = @(
    "--duration-ms", $DurationMs.ToString(),
    "--repeat", $Repeat.ToString(),
    "--affinity", "all-online",
    "--cpus", "all",
    "--seed", $seed
)

Invoke-Benchmark "native_like" "KNHV_NativeLikeBench.exe" (
    @("--mode", "baseline", "--workload", "cpu,mem") + $common +
    @("--out", (OutputPath "native_like.json"))) @(0) | Out-Null
Invoke-Benchmark "tsc_qpc" "KNHV_TscQpcBench.exe" (
    @("--mode", "baseline") + $common +
    @("--out", (OutputPath "tsc_qpc.json"))) @(0) | Out-Null
Invoke-Benchmark "vmexit" "KNHV_VmxExitBench.exe" @(
    "--mode", "synthetic", "--iterations", "1000000", "--repeat",
    $Repeat.ToString(), "--affinity", "all-online", "--cpus", "all",
    "--seed", $seed, "--out", (OutputPath "vmexit.json")) @(0) | Out-Null
Invoke-Benchmark "ept_hook" "KNHV_EptHookBench.exe" @(
    "--mode", "synthetic", "--profile", "no-hook,exec", "--pages", "64",
    "--duration-ms", $DurationMs.ToString(), "--repeat", $Repeat.ToString(),
    "--affinity", "all-online", "--cpus", "all", "--seed", $seed,
    "--out", (OutputPath "ept_hook.json")) @(0) | Out-Null
Invoke-Benchmark "device_io" "KNHV_DeviceIoBench.exe" @(
    "--mode", "synthetic", "--device-profile", "virtual", "--allow-dma",
    "--iterations", "1000000", "--repeat", $Repeat.ToString(),
    "--affinity", "all-online", "--cpus", "all", "--seed", $seed,
    "--out", (OutputPath "device_io.json")) @(0) | Out-Null

if (-not $SkipNativeGate) {
    Invoke-Benchmark "native_l0" "KNHV_NativeLikeBench.exe" @(
        "--mode", "native-l0", "--require-owner", "knhv", "--duration-ms",
        "100", "--repeat", "1", "--affinity", "all-online", "--cpus", "all",
        "--seed", $seed, "--out", (OutputPath "native_l0.json")) @(0, 10) | Out-Null
    Invoke-Benchmark "compare" "KNHV_NativeLikeBench.exe" @(
        "--compare", "--baseline", (OutputPath "native_like.json"),
        "--candidate", (OutputPath "native_l0.json"), "--out",
        (OutputPath "native_like_compare.json")) @(0, 12) | Out-Null
}

$manifest = [ordered]@{
    schema = "knhv-bench-run-1"
    created_at = (Get-Date).ToString("o")
    repository = $repoRoot
    configuration = $Configuration
    duration_ms = $DurationMs
    repeat = $Repeat
    seed = [UInt64]$seed
    execution_scope = "host-only-and-synthetic"
    physical_dma_enabled = $false
    release_ready = $false
    records = $records
}
$manifestPath = Join-Path $OutputDirectory "run.json"
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Output ("Benchmark run completed: {0}" -f $OutputDirectory)
Write-Output ("Manifest: {0}" -f $manifestPath)
