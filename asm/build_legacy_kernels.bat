@echo off
REM ============================================================================
REM build_legacy_kernels.bat - Build Resurrected Legacy Kernels
REM ============================================================================

cd /d d:\src\asm

REM Find VS2022
for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

if not defined VSPATH (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS2022 found at: %VSPATH%

REM Find MSVC version
set VCTOOLS=%VSPATH%\VC\Tools\MSVC
for /f %%i in ('dir /b /ad "%VCTOOLS%" ^| findstr /r "^[0-9]"') do set MSVCVER=%%i
echo [INFO] Using MSVC: %MSVCVER%

set ML64="%VCTOOLS%\%MSVCVER%\bin\Hostx64\x64\ml64.exe"
set LIBTOOL="%VCTOOLS%\%MSVCVER%\bin\Hostx64\x64\lib.exe"

echo ============================================
echo Building Sovereign Legacy Kernels
echo ============================================
echo.

REM Assemble MASM code
echo [1/2] Assembling Sovereign_Legacy_Kernels.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_Legacy_Kernels.obj Sovereign_Legacy_Kernels.asm
if errorlevel 1 (
    echo [ERROR] MASM assembly failed
    exit /b 1
)
echo [OK] Sovereign_Legacy_Kernels.obj
echo.

REM Create static library
echo [2/2] Creating library...
if exist Sovereign_Legacy_Kernels.lib del Sovereign_Legacy_Kernels.lib
%LIBTOOL% /OUT:Sovereign_Legacy_Kernels.lib Sovereign_Legacy_Kernels.obj
echo [OK] Sovereign_Legacy_Kernels.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Files created:
echo   - Sovereign_Legacy_Kernels.obj
echo   - Sovereign_Legacy_Kernels.lib
echo.
echo Exports:
echo   - Sovereign_FlashAttentionV2_F32
echo   - Sovereign_FastTokenScan
echo   - Sovereign_SVD_Compress_F32
echo   - Sovereign_TokenMerge_AVX512
echo   - Sovereign_Q4_0_Q8_0_MatMul
echo.
echo C API:
echo   - flash_attention_v2_f32
echo   - fast_token_scan
echo   - svd_compress_f32
echo   - token_merge_avx512
echo   - q4_0_q8_0_matmul
echo.
