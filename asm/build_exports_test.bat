@echo off
cd /d d:\src\asm

REM Setup VS2022 environment
for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"

echo Building export validation test...
cl.exe /O2 /Fe:test_exports_only.exe test_exports_only.cpp Sovereign_Legacy_Kernels.lib kernel32.lib /link /SUBSYSTEM:CONSOLE /NODEFAULTLIB:uuid.lib
if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo.
echo Running test...
test_exports_only.exe
