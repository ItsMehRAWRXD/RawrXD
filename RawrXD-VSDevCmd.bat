@echo off
REM RawrXD-VSDevCmd.bat
REM Launches Visual Studio Developer Command Prompt with RawrXD environment
REM Usage: Double-click or run from cmd/powershell

title RawrXD VS Developer Command Prompt

REM Find Visual Studio installation
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist %VSWHERE% (
    for /f "delims=" %%i in ('%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do (
        set VSINSTALLDIR=%%i
    )
) else (
    echo vswhere.exe not found. Installing VS Build Tools...
    exit /b 1
)

if not defined VSINSTALLDIR (
    echo Visual Studio not found. Install VS 2022 with C++ workload.
    exit /b 1
)

echo Found VS at: %VSINSTALLDIR%

REM Call vcvars64.bat to set up environment
call "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat"

REM Set RawrXD-specific environment
set RAWRXD_ROOT=%~dp0
set RAWRXD_BUILD_DIR=%RAWRXD_ROOT%build_vs

echo.
echo ============================================
echo RawrXD VS Developer Command Prompt Ready
echo ============================================
echo Root: %RAWRXD_ROOT%
echo Build: %RAWRXD_BUILD_DIR%
echo.
echo Available commands:
echo   cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=cmake/RawrXDToolchain.cmake ..
echo   cmake --build . --config Release
echo   cmake --build . --config Debug
echo   devenv RawrXD.sln
echo   .\RawrXD-VSBuild.ps1 -Config All -RunTests
echo ============================================
echo.

cmd /k