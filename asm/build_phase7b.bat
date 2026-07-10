@echo off
REM ============================================================================
REM build_phase7b.bat - Build Phase 7B Optimized Kernels
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
echo Building Phase 7B Optimized Kernels
echo ============================================
echo.

REM Assemble AVX-512 Q4Q8 MatMul
echo [1/2] Assembling Sovereign_Q4Q8_MatMul_AVX512_v2.asm...
%ML64% /c /W3 /Zi /Fo Sovereign_Q4Q8_MatMul_AVX512_v2.obj Sovereign_Q4Q8_MatMul_AVX512_v2.asm
if errorlevel 1 (
    echo [ERROR] MASM assembly failed
    exit /b 1
)
echo [OK] Sovereign_Q4Q8_MatMul_AVX512_v2.obj
echo.

REM Create library
echo [2/2] Creating library...
if exist Sovereign_Phase7B.lib del Sovereign_Phase7B.lib
%LIBTOOL% /OUT:Sovereign_Phase7B.lib Sovereign_Q4Q8_MatMul_AVX512_v2.obj
echo [OK] Sovereign_Phase7B.lib
echo.

echo ============================================
echo Phase 7B Build Complete
echo ============================================
echo.
echo Exports:
echo   - q4q8_matmul_avx512
echo.
