@echo off
REM ============================================================================
REM Build Script: Kernel Dispatch Test
REM ============================================================================

setlocal enabledelayedexpansion

REM Setup VS2022 environment
for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul') do set VSPATH=%%i

if not defined VSPATH (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set CL="cl.exe"
set LINK="link.exe"

echo ============================================
echo Building Kernel Dispatch Test
echo Using MSVC: %MSVCVER%
echo ============================================
echo.

REM Compile C++ dispatch layer
echo [1/3] Compiling Sovereign_KernelDispatch.cpp...
%CL% /c /O2 /W4 /EHsc /Zi /Fo Sovereign_KernelDispatch.obj ^
    /I. ^
    Sovereign_KernelDispatch.cpp
if errorlevel 1 (
    echo ERROR: Dispatch compilation failed
    exit /b 1
)
echo      OK: Sovereign_KernelDispatch.obj
echo.

REM Compile test
echo [2/3] Compiling test_kernel_dispatch.cpp...
%CL% /c /O2 /W4 /EHsc /Zi /Fo test_kernel_dispatch.obj ^
    /I. ^
    test_kernel_dispatch.cpp
if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)
echo      OK: test_kernel_dispatch.obj
echo.

REM Link everything
echo [3/3] Linking test executable...
%LINK% /OUT:test_kernel_dispatch.exe ^
    /SUBSYSTEM:CONSOLE ^
    /DEBUG ^
    test_kernel_dispatch.obj ^
    Sovereign_KernelDispatch.obj ^
    Sovereign_RMSNorm.obj ^
    Sovereign_RoPE.obj ^
    Sovereign_ResidualAdd.obj ^
    Sovereign_Q4K_Dequant.obj ^
    msvcrt.lib ^
    kernel32.lib
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo      OK: test_kernel_dispatch.exe
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Run the test with:
echo   .\test_kernel_dispatch.exe
echo.

endlocal
