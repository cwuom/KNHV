[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath,
    [Parameter(Mandatory = $true)]
    [string]$Certificate,
    [string]$Password,
    [string]$TimestampUrl,
    [string]$SignTool,
    [switch]$AllowUntrustedTestCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverItem = Get-Item -LiteralPath $DriverPath -ErrorAction SilentlyContinue
if (-not $driverItem) {
    # keep discovery limited to the requested artifact category when a caller
    # supplies a stale or generator-specific path
    $driverParent = Split-Path -Parent ([IO.Path]::GetFullPath($DriverPath))
    $matches = @(Get-ChildItem -LiteralPath $driverParent -Filter ([IO.Path]::GetFileName($DriverPath)) -File -Recurse -ErrorAction SilentlyContinue)
    if ($matches.Count -eq 1) { $driverItem = $matches[0] }
}
if (-not $driverItem) { throw "Driver not found: $DriverPath" }
$driver = $driverItem.FullName
$cert = (Resolve-Path -LiteralPath $Certificate -ErrorAction Stop).Path

function Find-SignTool([string]$RequestedPath) {
    if ($RequestedPath) {
        if (-not (Test-Path -LiteralPath $RequestedPath)) { throw "signtool.exe not found: $RequestedPath" }
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }
    if ($env:SIGNTOOL_PATH -and (Test-Path -LiteralPath $env:SIGNTOOL_PATH)) {
        return (Resolve-Path -LiteralPath $env:SIGNTOOL_PATH).Path
    }
    $pathCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    $fromPath = if ($pathCommand) { $pathCommand.Source } else { $null }
    if ($fromPath) { return $fromPath }

    $roots = @()
    if ($env:WindowsSdkDir) {
        $sdkRoot = $env:WindowsSdkDir.TrimEnd('\')
        if ($env:WindowsSDKVersion) {
            $version = $env:WindowsSDKVersion.Trim('\')
            $roots += Join-Path $sdkRoot ("bin\{0}" -f $version)
        }
        $roots += Join-Path $sdkRoot "bin"
    }
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $programFiles = $env:ProgramFiles
    $roots += Join-Path $programFilesX86 "Windows Kits\10\bin"
    $roots += Join-Path $programFiles "Windows Kits\10\bin"
    $found = foreach ($root in ($roots | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue
        }
    }
    $selected = $found | Sort-Object FullName -Descending | Select-Object -First 1
    if ($selected) { return $selected.FullName }
    throw "signtool.exe was not found. Install the Windows SDK or pass -SignTool explicitly."
}

$signtool = Find-SignTool $SignTool
$signArgs = @("sign", "/v", "/fd", "SHA256", "/f", $cert)
if ($Password) { $signArgs += @("/p", $Password) }
if ($TimestampUrl) { $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256") }

# A PFX may contain a Root CA and a leaf (older generated bundles did). Select
# the end-entity code-signing certificate by thumbprint so signing is
# deterministic on machines that retain older test certificates in their
# stores.
if ($Password -or [IO.Path]::GetExtension($cert).ToLowerInvariant() -eq ".pfx") {
    try {
        $pfxCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $pfxFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        $pfxCollection.Import($cert, $Password, $pfxFlags)
        $leafCandidates = @($pfxCollection | Where-Object {
            $_.HasPrivateKey -and
            @($_.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
                ForEach-Object { $_.Format($false) }) -join ";" -match "1\.3\.6\.1\.5\.5\.7\.3\.3"
        })
        if ($leafCandidates.Count -eq 1) {
            $signArgs += @("/sha1", $leafCandidates[0].Thumbprint)
        }
        elseif ($leafCandidates.Count -gt 1) {
            $selectedLeaf = $leafCandidates | Sort-Object NotAfter -Descending | Select-Object -First 1
            $signArgs += @("/sha1", $selectedLeaf.Thumbprint)
        }
    }
    catch {
        Write-Warning ("Could not inspect the PFX to select a leaf certificate; signtool will apply its normal selection rules: {0}" -f $_.Exception.Message)
    }
}
$signArgs += $driver

Write-Host "Signing $driver"
& $signtool @signArgs
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE." }

# First validate the embedded Authenticode signature itself. A local test
# chain commonly reports Status=Unknown because its root is not in the Windows
# trust policy; that is different from a missing or hash-mismatched signature.
$authenticode = Get-AuthenticodeSignature -LiteralPath $driver
if (-not $authenticode.SignerCertificate) {
    throw "The signed driver has no embedded signer certificate."
}
if ($authenticode.Status -eq "NotSigned" -or $authenticode.Status -eq "HashMismatch" -or
    $authenticode.Status -eq "NotTrusted") {
    $statusMessage = if ($authenticode.StatusMessage) { $authenticode.StatusMessage } else { $authenticode.Status }
    throw "Authenticode signature validation failed ($($authenticode.Status)): $statusMessage"
}
if ($authenticode.Status -eq "Unknown" -or $authenticode.Status -eq "UnknownError") {
    $statusMessage = if ($authenticode.StatusMessage) { $authenticode.StatusMessage } else { $authenticode.Status }
    $testRootUntrusted = $statusMessage -match "not trusted|terminated in a root|root.*not trusted|不受信任|不受信任的根|0x800B0109|0x80096010|0x800B010A"
    # Get-AuthenticodeSignature localizes this trust error.  The generated
    # certificate is already known to be a private test certificate, so the
    # explicit allow switch is authoritative even when the localized text does
    # not match the fallback patterns below.
    if (-not $AllowUntrustedTestCertificate -and -not $testRootUntrusted) {
        throw "Authenticode signature validation failed ($($authenticode.Status)): $statusMessage"
    }
    Write-Warning "The embedded signature is cryptographically present, but Windows does not trust the private test root in this store."
}
Write-Host ("Embedded signature: {0}; signer: {1}" -f $authenticode.Status, $authenticode.SignerCertificate.Subject)

# Ask signtool for the actual kernel policy result as well. Microsoft's /kp
# policy intentionally rejects a private test root on a normal machine. Do
# not hide that fact, but do not report it as a malformed signature when this
# task explicitly generated the local test certificate.
$savedErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $kpOutput = @(& $signtool verify /v /kp $driver 2>&1)
    $kpExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $savedErrorAction
}
if ($kpExitCode -ne 0) {
    $kpText = ($kpOutput -join "`n")
    $knownUntrustedRoot = $kpText -match "not trusted by the trust provider|not trusted|terminated in a root|root.*not trusted|does not chain to a Microsoft Root|Microsoft Root Cert|不受信任|不受信任的根|微软根证书|0x800B0109|0x80096010|0x800B010A"
    if ($AllowUntrustedTestCertificate -and $knownUntrustedRoot) {
        Write-Warning "signtool /kp rejected the private test root. The SYS is correctly Authenticode-signed for local testing, but this is not Microsoft kernel-policy/production trust. Use an isolated test VM with the appropriate test-signing policy."
    }
    else {
        if ($kpText) { Write-Host $kpText }
        throw "signtool kernel-policy verification failed with exit code $kpExitCode."
    }
}
else {
    Write-Host "signtool /kp verification succeeded."
}

# Keep callers that invoke this script with the PowerShell call operator from
# observing signtool's expected /kp exit code (1 for an untrusted private test
# root) as the script's process exit code.
exit 0
