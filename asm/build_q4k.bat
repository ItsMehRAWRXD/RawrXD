@echo off
REM ============================================================================
REM Build Script: Sovereign Q4_K Dequant Kernel
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
set LIBTOOL="%VCTools%\%MSVCVER%\bin\Hostx64\x64\lib.exe"

echo ============================================
echo Building Sovereign Q4_K Dequant Kernel
echo Using MSVC: %MSVCVER%
echo ============================================
echo.

REM Assemble MASM code
echo [1/2] Assembling Sovereign_Q4K_Dequant.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_Q4K_Dequant.obj Sovereign_Q4K_Dequant.asm
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo      OK: Sovereign_Q4K_Dequant.obj
echo.

REM Create static library
echo [2/2] Creating library...
if exist Sovereign_Q4K_Dequant.lib del Sovereign_Q4K_Dequant.lib
%LIBTOOL% /OUT:Sovereign_Q4K_Dequant.lib Sovereign_Q4K_Dequant.obj
echo      OK: Sovereign_Q4K_Dequant.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Files created:
echo   - Sovereign_Q4K_Dequant.obj
echo   - Sovereign_Q4K_Dequant.lib
echo.
echo Exports:
echo   - Sovereign_Q4K_Dequant_Block_AVX2
echo   - Sovereign_Q4K_Dequant_Tensor_AVX2
echo   - q4k_dequant_block (C API)
echo   - q4k_dequant_tensor (C API)
echo.

endlocal
