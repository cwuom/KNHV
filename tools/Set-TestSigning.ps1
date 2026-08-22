[CmdletBinding()]
param(
    [switch]$Enable,
    [switch]$Disable,
    [switch]$Status
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (($Enable.IsPresent -and $Disable.IsPresent) -or
    (($Enable.IsPresent -or $Disable.IsPresent) -and $Status.IsPresent)) {
    throw "Choose only one of -Enable, -Disable, or -Status."
}

$bcdedit = Join-Path $env:SystemRoot "System32\bcdedit.exe"
if (-not (Test-Path -LiteralPath $bcdedit)) {
    throw "bcdedit.exe was not found: $bcdedit"
}

function Get-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TestSigningState {
    $output = @(& $bcdedit /enum '{current}' 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw ("bcdedit /enum failed with exit code {0}: {1}" -f $exitCode, (($output -join " ").Trim()))
    }
    $line = $output | Where-Object { $_ -match "^\s*testsigning\s+" } | Select-Object -First 1
    if (-not $line) { return $false }
    return ($line -match "\b(on|yes|true|1)\b")
}

if (-not $Enable.IsPresent -and -not $Disable.IsPresent) {
    $enabled = Get-TestSigningState
    if ($enabled) {
        Write-Host "Windows TESTSIGNING: ON"
    }
    else {
        Write-Host "Windows TESTSIGNING: OFF"
    }
    exit 0
}

if (-not (Get-IsAdministrator)) {
    throw "Changing TESTSIGNING requires an elevated PowerShell window."
}

if ($Enable.IsPresent) {
    try {
        if (Confirm-SecureBootUEFI) {
            Write-Warning "Secure Boot is enabled. Windows may refuse TESTSIGNING at boot; do not disable Secure Boot on a production machine."
        }
    }
    catch {
        # Legacy BIOS or a restricted firmware query: bcdedit remains the
        # authoritative operation and its own error is handled below.
    }
    & $bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit could not enable TESTSIGNING (exit code $LASTEXITCODE). Secure Boot or policy may block test mode."
    }
    Write-Host "Windows TESTSIGNING is enabled. Reboot before loading the test-signed driver."
}
else {
    & $bcdedit /set testsigning off
    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit could not disable TESTSIGNING (exit code $LASTEXITCODE)."
    }
    Write-Host "Windows TESTSIGNING is disabled. Reboot to apply the change."
}
