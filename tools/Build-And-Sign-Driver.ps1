[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [string]$Certificate,
    [string]$Password,
    [string]$PasswordFile,
    [string]$TimestampUrl,
    [string]$SignTool,
    [string]$WdkRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$buildScript = Join-Path $PSScriptRoot "Build-Driver.ps1"
$signScript = Join-Path $PSScriptRoot "Sign-Driver.ps1"
$generateCertificateScript = Join-Path $PSScriptRoot "Generate-Test-Certificate.ps1"

$usingGeneratedCertificate = [string]::IsNullOrWhiteSpace($Certificate)
if ($usingGeneratedCertificate) {
    $Certificate = Join-Path $repoRoot "certs\KNHV_test.pfx"
    if (-not $PasswordFile) {
        $PasswordFile = Join-Path $repoRoot "certs\KNHV_test.pwd"
    }
    # Run the generator on every automatic-signing invocation. It reuses a
    # valid chain, but repairs the old single self-signed PFX that this project
    # used before the Root-CA + leaf layout was introduced.
    Write-Host "Ensuring the local Root CA + kernel code-signing certificate"
    & $generateCertificateScript
    if ($LASTEXITCODE -ne 0) {
        throw "Test certificate generation failed with exit code $LASTEXITCODE."
    }
}

if (-not $Password -and $PasswordFile -and (Test-Path -LiteralPath $PasswordFile)) {
    $Password = (Get-Content -LiteralPath $PasswordFile -Raw).Trim()
}
if (-not (Test-Path -LiteralPath $Certificate)) {
    throw "Signing certificate was not found: $Certificate"
}

$buildArgs = @{ Configuration = $Configuration }
if ($WdkRoot) { $buildArgs.WdkRoot = $WdkRoot }

Write-Host "Building SYS and PDB ($Configuration)"
& $buildScript @buildArgs
if ($LASTEXITCODE -ne 0) {
    throw "Driver build failed with exit code $LASTEXITCODE."
}

$driverPath = Join-Path $repoRoot (Join-Path "build\vscode" (Join-Path $Configuration "KNHV.sys"))
$signArgs = @{
    DriverPath = $driverPath
    Certificate = $Certificate
}
if ($Password) { $signArgs.Password = $Password }
if ($TimestampUrl) { $signArgs.TimestampUrl = $TimestampUrl }
if ($SignTool) { $signArgs.SignTool = $SignTool }
if ($usingGeneratedCertificate) { $signArgs.AllowUntrustedTestCertificate = $true }

Write-Host "Signing KNHV.sys"
& $signScript @signArgs
if ($LASTEXITCODE -ne 0) {
    throw "Driver signing failed with exit code $LASTEXITCODE."
}

Write-Host "Signed SYS: $driverPath"
