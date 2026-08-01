@echo off
setlocal enabledelayedexpansion
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "INCLUDE=!INCLUDE!;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um"
set "LIB=!LIB!;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
cl /O2 /EHsc /std:c++17 /Fe:d:\rawrxd-ci-bootstrap\build\bin\SovereignIDE.exe d:\rawrxd-ci-bootstrap\src\SovereignIDE.cpp user32.lib gdi32.lib comdlg32.lib
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
echo Build complete: d:\rawrxd-ci-bootstrap\build\bin\SovereignIDE.exe
