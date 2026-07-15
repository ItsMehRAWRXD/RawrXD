@echo off
REM Build script for RawrXD-Script DAP Debugger
REM Requires: Visual Studio 2022 (cl.exe)

echo ============================================
echo RawrXD-Script DAP Server Build
echo ============================================
echo.

set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
    echo ERROR: vswhere.exe not found. Please install Visual Studio 2022.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set VS_PATH=%%i
)

call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo ERROR: Failed to initialize VS environment
    exit /b 1
)

echo Building RawrXD-Script DAP Server...
echo.

cl /O2 /EHsc /std:c++20 /W4 /Fe:rxd-script-dap.exe^
    RawrXDScriptDAPServer.cpp^
    RawrXDScriptDAPAdapter.cpp^
    /link /SUBSYSTEM:CONSOLE

if errorlevel 1 (
    echo.
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ============================================
echo Build successful: rxd-script-dap.exe
echo ============================================
echo.
echo Usage:
echo   rxd-script-dap.exe              - Run DAP server
echo   rxd-script-dap.exe --log        - Run with logging
echo.
echo Integration:
echo   1. Copy rxd-script-dap.exe to your IDE's debugger path
echo   2. Configure launch.json for "type": "rawrxd-script"
echo   3. Set breakpoints and debug!
echo.

pause
