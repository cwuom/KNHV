@echo off
setlocal
where cl.exe >nul 2>nul
if errorlevel 1 (
    echo cl.exe not found.
    echo Run this from an x64 Native Tools Command Prompt for Visual Studio.
    exit /b 1
)
set "output_root=%~dp0..\build\standalone"
for %%I in ("%output_root%") do set "output_root=%%~fI"
set "output_bin=%output_root%\bin"
set "output_obj=%output_root%\native_vmx_probe.obj"
if not exist "%output_bin%" mkdir "%output_bin%"
cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /WX /MT /Zi ^
    "%~dp0native_vmx_probe.cpp" ^
    /Fo:"%output_obj%" ^
    /Fe:"%output_bin%\KNHV_NativeVmxProbe.exe" ^
    /Fd:"%output_root%\KNHV_NativeVmxProbe.compile.pdb" ^
    /link /DEBUG /INCREMENTAL:NO /PDB:"%output_root%\KNHV_NativeVmxProbe.pdb"
if errorlevel 1 exit /b %errorlevel%
echo Built: %output_bin%\KNHV_NativeVmxProbe.exe
