@echo off
REM ============================================================================
REM Build Script: Sovereign ResidualAdd + LayerNorm Kernels
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
echo Building Sovereign ResidualAdd + LayerNorm
echo Using MSVC: %MSVCVER%
echo ============================================
echo.

REM Assemble ResidualAdd
echo [1/4] Assembling Sovereign_ResidualAdd.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_ResidualAdd.obj Sovereign_ResidualAdd.asm
if errorlevel 1 (
    echo ERROR: ResidualAdd assembly failed
    exit /b 1
)
echo      OK: Sovereign_ResidualAdd.obj
echo.

REM Assemble LayerNorm
echo [2/4] Assembling Sovereign_LayerNorm.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_LayerNorm.obj Sovereign_LayerNorm.asm
if errorlevel 1 (
    echo ERROR: LayerNorm assembly failed
    exit /b 1
)
echo      OK: Sovereign_LayerNorm.obj
echo.

REM Create ResidualAdd library
echo [3/4] Creating ResidualAdd library...
if exist Sovereign_ResidualAdd.lib del Sovereign_ResidualAdd.lib
%LIBTOOL% /OUT:Sovereign_ResidualAdd.lib Sovereign_ResidualAdd.obj
echo      OK: Sovereign_ResidualAdd.lib
echo.

REM Create LayerNorm library
echo [4/4] Creating LayerNorm library...
if exist Sovereign_LayerNorm.lib del Sovereign_LayerNorm.lib
%LIBTOOL% /OUT:Sovereign_LayerNorm.lib Sovereign_LayerNorm.obj
echo      OK: Sovereign_LayerNorm.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Files created:
echo   - Sovereign_ResidualAdd.obj / .lib
echo   - Sovereign_LayerNorm.obj / .lib
echo.
echo ResidualAdd Exports:
echo   - Sovereign_ResidualAdd_F32_AVX2
echo   - Sovereign_ResidualAdd_F32_InPlace_AVX2
echo   - Sovereign_ResidualAdd_Scaled_F32_AVX2
echo   - residual_add_f32 (C API)
echo   - residual_add_f32_inplace (C API)
echo   - residual_add_f32_scaled (C API)
echo.
echo LayerNorm Exports:
echo   - Sovereign_LayerNorm_F32_AVX2
echo   - layer_norm_f32 (C API)
echo.

endlocal
