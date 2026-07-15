@echo off
REM ============================================================================
REM Build Script: Sovereign RoPE Kernel
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
echo Building Sovereign RoPE Kernel
echo Using MSVC: %MSVCVER%
echo ============================================
echo.

REM Assemble MASM code
echo [1/2] Assembling Sovereign_RoPE.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_RoPE.obj Sovereign_RoPE.asm
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo      OK: Sovereign_RoPE.obj
echo.

REM Create static library
echo [2/2] Creating library...
if exist Sovereign_RoPE.lib del Sovereign_RoPE.lib
%LIBTOOL% /OUT:Sovereign_RoPE.lib Sovereign_RoPE.obj
echo      OK: Sovereign_RoPE.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Files created:
echo   - Sovereign_RoPE.obj
echo   - Sovereign_RoPE.lib
echo   - Sovereign_RoPE.h (C++ interface)
echo.
echo Exports:
echo   - Sovereign_RoPE_Precompute_FreqCache
echo   - Sovereign_RoPE_Apply_F32_AVX2
echo   - Sovereign_RoPE_LlamaStyle_F32
echo   - rope_precompute_cache (C API)
echo   - rope_apply_f32 (C API)
echo   - rope_apply_llama_f32 (C API)
echo.

endlocal
