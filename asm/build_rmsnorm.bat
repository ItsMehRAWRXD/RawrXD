@echo off
REM ============================================================================
REM Build Script: Sovereign RMSNorm Kernel
REM ============================================================================

setlocal enabledelayedexpansion

REM Find VS2022
for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul') do set VSPATH=%%i

if not defined VSPATH (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

set VCTools=%VSPATH%\VC\Tools\MSVC
for /f %%i in ('dir /b /ad "%VCTools%" ^| findstr /r "^[0-9]"') do set MSVCVER=%%i

set ML64="%VCTools%\%MSVCVER%\bin\Hostx64\x64\ml64.exe"

echo ============================================
echo Building Sovereign RMSNorm Kernel
echo Using MSVC: %MSVCVER%
echo ============================================
echo.

REM Assemble MASM code
echo [1/2] Assembling Sovereign_RMSNorm.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_RMSNorm.obj Sovereign_RMSNorm.asm
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo      OK: Sovereign_RMSNorm.obj
echo.

REM Create static library
echo [2/2] Creating library...
if exist Sovereign_RMSNorm.lib del Sovereign_RMSNorm.lib
set LIBTOOL="%VCTools%\%MSVCVER%\bin\Hostx64\x64\lib.exe"
%LIBTOOL% /OUT:Sovereign_RMSNorm.lib Sovereign_RMSNorm.obj
echo      OK: Sovereign_RMSNorm.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Files created:
echo   - Sovereign_RMSNorm.obj
echo   - Sovereign_RMSNorm.lib
echo   - Sovereign_RMSNorm.h (C++ interface)
echo.
echo Exports:
echo   - Sovereign_RMSNorm_F32_AVX2
echo   - Sovereign_RMSNorm_F32_InPlace_AVX2
echo   - rms_norm_f32 (C API)
echo   - rms_norm_f32_inplace (C API)
echo.

endlocal
