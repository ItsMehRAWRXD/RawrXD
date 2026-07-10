@echo off
REM ============================================================================
REM build_masm_kernels.bat - Build Real MASM Kernels
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
echo Building Real MASM Kernels
echo ============================================
echo.

REM Assemble MatMul_Q4_Q8
echo [1/3] Assembling MatMul_Q4_Q8.asm...
%ML64% /c /W3 /Zi /Fo MatMul_Q4_Q8.obj MatMul_Q4_Q8.asm
if errorlevel 1 (
    echo [ERROR] MatMul_Q4_Q8 assembly failed
    exit /b 1
)
echo [OK] MatMul_Q4_Q8.obj
echo.

REM Assemble FlashAttentionV2_MASM
echo [2/3] Assembling FlashAttentionV2_MASM.asm...
%ML64% /c /W3 /Zi /Fo FlashAttentionV2_MASM.obj FlashAttentionV2_MASM.asm
if errorlevel 1 (
    echo [ERROR] FlashAttentionV2_MASM assembly failed
    exit /b 1
)
echo [OK] FlashAttentionV2_MASM.obj
echo.

REM Create library
echo [3/3] Creating library...
if exist Sovereign_MASM_Kernels.lib del Sovereign_MASM_Kernels.lib
%LIBTOOL% /OUT:Sovereign_MASM_Kernels.lib MatMul_Q4_Q8.obj FlashAttentionV2_MASM.obj
echo [OK] Sovereign_MASM_Kernels.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Exports:
echo   - matmul_q4_q8
echo   - flash_attention_v2_masm
echo.
