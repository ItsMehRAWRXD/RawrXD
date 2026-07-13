@echo off
REM ============================================================================
REM build_intrinsics.bat - Build Intrinsics-Based Optimized Kernels
REM ============================================================================

cd /d d:\src\asm

REM Find VS2022
for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

if not defined VSPATH (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS2022 found at: %VSPATH%

REM Setup environment
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"

echo ============================================
echo Building Intrinsics-Based Kernels
echo ============================================
echo.

REM Compile Q4Q8 MatMul Intrinsics
echo [1/3] Compiling Sovereign_Q4Q8_MatMul_Intrinsics.cpp...
cl.exe /c /O2 /EHsc /arch:AVX2 /Fo Sovereign_Q4Q8_MatMul_Intrinsics.obj Sovereign_Q4Q8_MatMul_Intrinsics.cpp
if errorlevel 1 (
    echo [ERROR] Q4Q8 MatMul compilation failed
    exit /b 1
)
echo [OK] Sovereign_Q4Q8_MatMul_Intrinsics.obj
echo.

REM Compile FlashAttention Intrinsics
echo [2/3] Compiling Sovereign_FlashAttention_Intrinsics.cpp...
cl.exe /c /O2 /EHsc /arch:AVX2 /Fo Sovereign_FlashAttention_Intrinsics.obj Sovereign_FlashAttention_Intrinsics.cpp
if errorlevel 1 (
    echo [ERROR] FlashAttention compilation failed
    exit /b 1
)
echo [OK] Sovereign_FlashAttention_Intrinsics.obj
echo.

REM Create library
echo [3/3] Creating library...
if exist Sovereign_Intrinsics.lib del Sovereign_Intrinsics.lib
lib.exe /OUT:Sovereign_Intrinsics.lib Sovereign_Q4Q8_MatMul_Intrinsics.obj Sovereign_FlashAttention_Intrinsics.obj
echo [OK] Sovereign_Intrinsics.lib
echo.

echo ============================================
echo Build Complete
echo ============================================
echo.
echo Files created:
echo   - Sovereign_Q4Q8_MatMul_Intrinsics.obj
echo   - Sovereign_FlashAttention_Intrinsics.obj
echo   - Sovereign_Intrinsics.lib
echo.
echo Exports:
echo   - Sovereign_Q4Q8_MatMul_Intrinsics
echo   - Sovereign_FlashAttentionV2_Intrinsics
echo.
