@echo off
:: Build script for Sovereign CLI v4.0.0 - Phase 7 Full Integration
:: This compiles the complete CLI with all Phase 7 components

echo ============================================
echo Building Sovereign CLI v4.0.0
echo Phase 7 Full Integration
echo ============================================
echo.

:: Setup MSVC environment
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
)
if errorlevel 1 (
    echo ERROR: Could not find MSVC environment
    exit /b 1
)

set SOURCE=sovereign_cli_integrated.cpp
set OUTPUT=SovereignCLI_Integrated.exe
set LIBS="d:\src\asm\Sovereign_Legacy_Kernels.lib" "d:\src\asm\Sovereign_Intrinsics.lib" "d:\src\asm\Titan_KernelIntegration.lib"

echo Compiling %SOURCE%...
echo.

cl.exe /EHsc /O2 /std:c++17 /W3 /I. /I"d:\rawrxd\src\core\execution" /I"d:\src\asm" %SOURCE% /Fe%OUTPUT% /link %LIBS%

if errorlevel 1 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo Output: %OUTPUT%
for %%I in (%OUTPUT%) do echo Size: %%~zI bytes
echo.
echo Run with: %OUTPUT%
echo ============================================
