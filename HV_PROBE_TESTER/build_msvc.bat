@echo off
setlocal
where cl.exe >nul 2>nul
if errorlevel 1 (
    echo cl.exe not found.
    echo Run this from an x64 Native Tools Command Prompt for Visual Studio.
    exit /b 1
)
cl.exe /nologo /std:c++17 /O2 /EHsc /W4 hv_probe.cpp /Fe:hv_probe.exe
if errorlevel 1 exit /b %errorlevel%
echo Built: hv_probe.exe
