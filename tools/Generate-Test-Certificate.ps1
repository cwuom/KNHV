[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$Recreate
)

# This script intentionally creates a private, local test chain only. It is
# not a replacement for Microsoft's production/attestation signing process.
# Keep the implementation compatible with Windows PowerShell 5.1.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repoRoot "certs"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$rootSubject = "CN=KNHV Test Root CA"
$leafSubject = "CN=KNHV Test Code Signing"
$rootPath = Join-Path $OutputDirectory "KNHV_test_root.cer"
$leafPath = Join-Path $OutputDirectory "KNHV_test.cer"
$pfxPath = Join-Path $OutputDirectory "KNHV_test.pfx"
$passwordPath = Join-Path $OutputDirectory "KNHV_test.pwd"

function New-RandomPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $value = ([Convert]::ToBase64String($bytes) -replace "[^A-Za-z0-9]", "")
    if ($value.Length -lt 32) { throw "Could not generate a sufficiently long certificate password." }
    return $value.Substring(0, 32)
}

function Get-Password {
    if (Test-Path -LiteralPath $passwordPath) {
        $existing = (Get-Content -LiteralPath $passwordPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($existing)) { return $existing }
    }
    $newPassword = New-RandomPassword
    Set-Content -LiteralPath $passwordPath -Value $newPassword -Encoding ASCII -NoNewline
    return $newPassword
}

function Remove-GeneratedStoreCertificates {
    # Remove only subjects used by this repository and by the earlier probe
    # certificates. Never clear a complete certificate store.
    $subjects = @(
        $rootSubject,
        $leafSubject,
        "CN=KNHV Test Root Code Signing 2026",
        "CN=KNHV Test Root Critical 2026",
        "CN=KNHV Test Kernel Signing 2026"
    )
    $stores = @("Cert:\CurrentUser\My", "Cert:\CurrentUser\Root", "Cert:\CurrentUser\TrustedPublisher")
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $stores += @("Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher")
    }
    foreach ($storeName in $stores) {
        try {
            $items = @(Get-ChildItem -LiteralPath $storeName -ErrorAction Stop |
                Where-Object { $subjects -contains $_.Subject })
            foreach ($item in $items) {
                try { Remove-Item -LiteralPath $item.PSPath -Force -ErrorAction Stop }
                catch {
                    Write-Warning ("Could not remove old certificate {0} from {1}: {2}" -f $item.Thumbprint, $storeName, $_.Exception.Message)
                }
            }
        }
        catch { Write-Warning ("Could not inspect certificate store {0}: {1}" -f $storeName, $_.Exception.Message) }
    }
}

function Remove-OldArtifacts {
    # Probe files were created by early signing experiments. They are generated
    # data, not source, and are safe to remove from certs/.
    foreach ($pattern in @("probe_*", "tmp-*")) {
        @(Get-ChildItem -LiteralPath $OutputDirectory -Filter $pattern -File -ErrorAction SilentlyContinue) |
            ForEach-Object {
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop }
                catch { Write-Warning ("Could not remove old artifact {0}: {1}" -f $_.FullName, $_.Exception.Message) }
            }
    }
}

function Get-PfxLeaf([string]$Path, [string]$PfxPassword) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        $collection.Import($Path, $PfxPassword, $flags)
        return ($collection | Where-Object { $_.Subject -eq $leafSubject -and $_.HasPrivateKey } | Select-Object -First 1)
    }
    catch { return $null }
}

function Test-ExistingChain([string]$PfxPassword) {
    $leaf = Get-PfxLeaf $pfxPath $PfxPassword
    if (-not $leaf -or $leaf.Issuer -ne $rootSubject) { return $false }
    if (-not (Test-Path -LiteralPath $rootPath)) { return $false }
    try {
        # Keep the signing PFX end-entity-only.  Including the private root as
        # an additional PFX certificate makes signtool consider the CA as a
        # second signer; the root is exported separately and installed in the
        # trust store instead.
        $pfxCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $pfxFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        $pfxCollection.Import($pfxPath, $PfxPassword, $pfxFlags)
        if ($pfxCollection.Count -ne 1) { return $false }
        $root = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootPath)
        if ($root.Subject -ne $rootSubject -or $root.Issuer -ne $rootSubject) { return $false }
        if ($leaf.NotAfter -lt (Get-Date).AddDays(1) -or $root.NotAfter -lt (Get-Date).AddDays(1)) { return $false }
        $eku = @($leaf.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" } | ForEach-Object { $_.Format($false) }) -join ";"
        if ($eku -notmatch "1\.3\.6\.1\.4\.1\.311\.10\.3\.6" -or $eku -notmatch "1\.3\.6\.1\.5\.5\.7\.3\.3") { return $false }
        return $true
    }
    catch { return $false }
}

function Try-InstallCertificate([string]$Path, [string]$Store) {
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)
        $existing = @(Get-ChildItem -LiteralPath $Store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })
        if ($existing.Count -gt 0) { return $true }
        # Import-Certificate can throw "UI is not allowed" in non-interactive
        # or policy-restricted sessions (notably for CurrentUser\Root).
        Import-Certificate -FilePath $Path -CertStoreLocation $Store -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning ("Could not install {0} into {1}: {2}" -f $Path, $Store, $_.Exception.Message)
        return $false
    }
}

$password = Get-Password
Remove-OldArtifacts

if (-not $Recreate -and (Test-ExistingChain $password)) {
    $existingLeaf = Get-PfxLeaf $pfxPath $password
    Write-Host "Existing KNHV test certificate chain is valid; reusing it."
}
else {
    Remove-GeneratedStoreCertificates
    foreach ($path in @($pfxPath, $leafPath, $rootPath)) {
        if (Test-Path -LiteralPath $path) {
            try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
            catch { throw ("Could not replace generated certificate file {0}: {1}" -f $path, $_.Exception.Message) }
        }
    }

    $rootExtensions = @("2.5.29.19={critical}{text}CA=true&pathlength=1")
    $root = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $rootSubject `
        -FriendlyName "KNHV local test root CA" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -TextExtension $rootExtensions `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(5)

    $leafExtensions = @(
        "2.5.29.19={critical}{text}CA=false",
        # Code Signing and Microsoft Kernel Mode Code Signing EKUs.
        "2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.6"
    )
    $leaf = New-SelfSignedCertificate `
        -Type Custom `
        -Subject $leafSubject `
        -FriendlyName "KNHV local test kernel code signing" `
        -Signer $root `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -TextExtension $leafExtensions `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(3)

    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    Export-PfxCertificate -Cert $leaf -FilePath $pfxPath -Password $securePassword -ChainOption EndEntityCertOnly -Force | Out-Null
    Export-Certificate -Cert $leaf -FilePath $leafPath -Type CERT -Force | Out-Null
    Export-Certificate -Cert $root -FilePath $rootPath -Type CERT -Force | Out-Null
    $existingLeaf = $leaf
}

# A test-signed kernel driver is normally evaluated against the machine stores.
# Prefer LocalMachine when this PowerShell is elevated, then fall back to the
# current-user stores. Store import failures are warnings only: certificate
# creation and file signing remain independent of enterprise trust policy.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$rootInstalled = $false
$leafInstalled = $false
if ($isAdministrator) {
    $rootInstalled = Try-InstallCertificate $rootPath "Cert:\LocalMachine\Root"
    $leafInstalled = Try-InstallCertificate $leafPath "Cert:\LocalMachine\TrustedPublisher"
}
if (-not $rootInstalled) {
    $rootInstalled = Try-InstallCertificate $rootPath "Cert:\CurrentUser\Root"
}
if (-not $leafInstalled) {
    $leafInstalled = Try-InstallCertificate $leafPath "Cert:\CurrentUser\TrustedPublisher"
}

Write-Host ("Test leaf: {0}" -f $existingLeaf.Subject)
Write-Host ("Issuer: {0}" -f $existingLeaf.Issuer)
Write-Host ("Thumbprint: {0}" -f $existingLeaf.Thumbprint)
Write-Host ("PFX: {0}" -f $pfxPath)
Write-Host ("Leaf certificate: {0}" -f $leafPath)
Write-Host ("Root certificate: {0}" -f $rootPath)
Write-Host ("Password file: {0}" -f $passwordPath)
if (-not $rootInstalled) {
    Write-Warning "The local root could not be added to a trusted Root store. The PFX and signature are still valid; test-signing policy must be configured on the isolated test machine."
}
if (-not $leafInstalled) {
    Write-Warning "The leaf could not be added to a trusted Publisher store. Signature verification can still be performed with the generated PFX."
}

# A successful key/certificate generation returns zero even when trust stores
# are policy-restricted. It is not production kernel signing.
exit 0
