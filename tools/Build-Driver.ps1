[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$ConfigureOnly,
    [string]$BuildDirectory,
    [string]$WdkRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
if (-not $BuildDirectory) {
    $BuildDirectory = Join-Path $repoRoot (Join-Path "build\vscode" $Configuration)
}
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)

# Fail early with an actionable message. ntddk.h and ntoskrnl.lib are WDK
# files; the Windows SDK alone cannot build or provide IntelliSense for this
# kernel driver.
$wdkSearchRoots = @(
    "C:\Program Files (x86)\Windows Kits\10\Include",
    "C:\Program Files\Windows Kits\10\Include"
)
if ($WdkRoot) {
    $wdkSearchRoots = @((Join-Path $WdkRoot "Include")) + $wdkSearchRoots
}
if ($env:WDKContentRoot) {
    $wdkSearchRoots = @((Join-Path $env:WDKContentRoot "Include")) + $wdkSearchRoots
}
$wdkHeader = Get-ChildItem -Path $wdkSearchRoots -Filter ntddk.h -File -Recurse -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $wdkHeader) {
    $searched = ($wdkSearchRoots -join "; ")
    throw "WDK was not found: ntddk.h is missing. Install the Windows Driver Kit matching the Windows SDK (searched: $searched), then reopen VS Code from a Developer PowerShell."
}
if ($WdkRoot) {
    $env:WDKContentRoot = [IO.Path]::GetFullPath($WdkRoot)
} elseif (-not $env:WDKContentRoot) {
    $wdkIncludeRoot = Split-Path -Parent (Split-Path -Parent $wdkHeader.FullName)
    $env:WDKContentRoot = Split-Path -Parent (Split-Path -Parent $wdkIncludeRoot)
}

function Find-VisualStudioDevCmd {
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $programFiles = $env:ProgramFiles
    $vswhereCandidates = @(
        (Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\Installer\vswhere.exe")
    )
    foreach ($vswhere in $vswhereCandidates) {
        if (Test-Path -LiteralPath $vswhere) {
            $installPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
            if ($installPath) {
                $candidate = Join-Path $installPath.Trim() "Common7\Tools\VsDevCmd.bat"
                if (Test-Path -LiteralPath $candidate) { return $candidate }
            }
        }
    }

    # VS installations do not always include vswhere (notably the preview/
    # vNext layout used by this workspace).  Fall back to the conventional
    # Community/Professional/Enterprise/BuildTools locations, preferring the
    # newest toolset first.  This keeps VS Code tasks self-contained when the
    # caller starts PowerShell outside a Developer Command Prompt.
    $knownCandidates = @(
        "18\Community", "18\Professional", "18\Enterprise", "18\BuildTools",
        "17\Community", "17\Professional", "17\Enterprise", "17\BuildTools",
        "16\Community", "16\Professional", "16\Enterprise", "16\BuildTools"
    ) | ForEach-Object {
        Join-Path $programFiles ("Microsoft Visual Studio\{0}\Common7\Tools\VsDevCmd.bat" -f $_)
    }
    foreach ($candidate in $knownCandidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Import-VisualStudioEnvironment([string]$DevCmd) {
    # VsDevCmd.bat modifies a child cmd.exe environment. Capture `set` and
    # import those values so subsequent CMake/MASM invocations use that toolset.
    $cmdLine = 'call "{0}" -arch=x64 -host_arch=x64 >nul && set' -f $DevCmd
    $environmentLines = & cmd.exe /d /s /c $cmdLine
    foreach ($line in $environmentLines) {
        $separator = $line.IndexOf("=")
        if ($separator -gt 0) {
            $name = $line.Substring(0, $separator)
            $value = $line.Substring($separator + 1)
            Set-Item -Path ("Env:" + $name) -Value $value
        }
    }
}

$devCmd = $null
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue) -or
    -not (Get-Command ml64.exe -ErrorAction SilentlyContinue)) {
    $devCmd = Find-VisualStudioDevCmd
    if ($devCmd) { Import-VisualStudioEnvironment $devCmd }
}
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue) -or
    -not (Get-Command ml64.exe -ErrorAction SilentlyContinue)) {
    throw "The MSVC x64 toolchain was not found (cl.exe/ml64.exe). Install the Visual Studio Desktop C++ workload and run this task from a Developer PowerShell."
}

$programFilesX86 = ${env:ProgramFiles(x86)}
$programFiles = $env:ProgramFiles
$cmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$cmake = if ($cmakeCommand) { $cmakeCommand.Source } else { $null }
if (-not $cmake) {
    $cmakeCandidates = @(
        (Join-Path $programFiles "CMake\bin\cmake.exe"),
        (Join-Path $programFilesX86 "CMake\bin\cmake.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\18\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\18\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe")
    )
    $cmake = $cmakeCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
if (-not $cmake) { throw "cmake.exe was not found. Install CMake or the Visual Studio CMake component." }

# VsDevCmd normally adds Ninja to PATH, but some VS installs expose the CMake
# component without exporting its private Ninja directory.  Locate it beside
# the selected CMake binary and prepend that directory before configuring.
$ninja = Get-Command ninja.exe -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ninja) {
    $cmakeDirectory = Split-Path -Parent $cmake
    $ninjaCandidates = @(
        (Join-Path $cmakeDirectory "..\..\Ninja\ninja.exe"),
        (Join-Path $cmakeDirectory "..\Ninja\ninja.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"),
        (Join-Path $programFiles "Microsoft Visual Studio\17\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe")
    )
    $ninjaPath = $ninjaCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if ($ninjaPath) {
        $env:Path = (Split-Path -Parent $ninjaPath) + ";" + $env:Path
        $ninja = Get-Command ninja.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    }
}

function Select-VisualStudioGenerator([string]$CMakePath, [string]$DevCmdPath) {
    $helpText = (& $CMakePath --help 2>$null) -join "`n"
    $supported = @([regex]::Matches(
        $helpText,
        # CMake marks the default generator with either '*' or '>' depending
        # on the release; non-default generators have no marker at all.
        '(?m)^\s*[>*]?\s*(Visual Studio \d+ \d{4})\s+=')) |
        ForEach-Object { $_.Groups[1].Value }

    $major = $null
    if ($DevCmdPath -and $DevCmdPath -match '\\Microsoft Visual Studio\\(?<version>[^\\]+)\\') {
        $vsVersion = $Matches.version
        if ($vsVersion -match '^\d+$' -and [int]$vsVersion -ge 15 -and [int]$vsVersion -le 18) {
            $major = [int]$vsVersion
        } elseif ($vsVersion -eq '2026') {
            $major = 18
        } elseif ($vsVersion -eq '2022') {
            $major = 17
        } elseif ($vsVersion -eq '2019') {
            $major = 16
        } elseif ($vsVersion -eq '2017') {
            $major = 15
        }
    } elseif ($env:VisualStudioVersion -and
              $env:VisualStudioVersion -match '^(?<major>\d+)') {
        $major = [int]$Matches.major
    }

    $yearByMajor = @{
        18 = 2026
        17 = 2022
        16 = 2019
        15 = 2017
    }
    if ($null -ne $major -and $yearByMajor.ContainsKey($major)) {
        $candidate = "Visual Studio $major $($yearByMajor[$major])"
        if ($supported -contains $candidate) { return $candidate }
    }

    $fallback = $supported | Select-Object -First 1
    if ($fallback) { return $fallback }
    throw "No supported Visual Studio generator was found in cmake --help. Install Visual Studio with the C++ workload or install Ninja."
}

$generator = if ($ninja) { "Ninja" } else {
    Select-VisualStudioGenerator -CMakePath $cmake -DevCmdPath $devCmd
}
$configureArgs = @("-S", $repoRoot, "-B", $BuildDirectory, "-G", $generator)
if ($generator -eq "Ninja") {
    $configureArgs += "-DCMAKE_BUILD_TYPE=$Configuration"
} else {
    $configureArgs += @("-A", "x64")
}
$configureArgs += @("-DNESTED_HV_SIGN=OFF", "-DNESTED_HV_BUILD_TESTS=ON")
if ($WdkRoot) { $configureArgs += "-DWDK_CONTENT_ROOT=$WdkRoot" }

Write-Host "Configuring $generator in $BuildDirectory"
& $cmake @configureArgs
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed with exit code $LASTEXITCODE." }
if ($ConfigureOnly) { exit 0 }

$buildArgs = @("--build", $BuildDirectory, "--config", $Configuration, "--parallel")
Write-Host "Building Nested_HV ($Configuration)"
& $cmake @buildArgs
if ($LASTEXITCODE -ne 0) { throw "CMake build failed with exit code $LASTEXITCODE." }

# Report both artifacts explicitly.  A kernel driver is not launched by VS
# Code; the SYS is loaded by the service manager and the matching PDB is used
# by WinDbg/symbol tooling.  Keep the check recursive for Visual Studio's
# multi-configuration generator, which may place outputs below <Config>\Debug.
$sysArtifacts = @(Get-ChildItem -LiteralPath $BuildDirectory -Filter "Nested_HV.sys" -File -Recurse -ErrorAction SilentlyContinue)
if ($sysArtifacts.Count -eq 0) {
    throw "Build completed but Nested_HV.sys was not found below $BuildDirectory."
}
foreach ($sysArtifact in $sysArtifacts) {
    Write-Host "SYS: $($sysArtifact.FullName) [$($sysArtifact.Length) bytes]"
    $pdbPath = Join-Path $sysArtifact.DirectoryName "Nested_HV.pdb"
    if (Test-Path -LiteralPath $pdbPath) {
        $pdb = Get-Item -LiteralPath $pdbPath
        Write-Host "PDB: $($pdb.FullName) [$($pdb.Length) bytes]"
    } else {
        throw "Nested_HV.sys was produced without its matching Nested_HV.pdb: $($sysArtifact.FullName)"
    }
}
