@echo off
REM ============================================================================
REM Build Script: Fused Q4_0 Quantized Matrix Multiplication Kernels
REM RawrXD Fix #4 - Hybrid Static/Dynamic Dispatch
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo Building RawrXD Quantized MatMul Kernels
echo ============================================================================

REM Check for Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio not found. Please install VS 2022.
    exit /b 1
)

REM Find VS installation path
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
    set "VSINSTALLPATH=%%i"
)

if not exist "%VSINSTALLPATH%" (
    echo ERROR: Could not find Visual Studio installation.
    exit /b 1
)

echo Found VS at: %VSINSTALLPATH%

REM Setup environment
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment.
    exit /b 1
)

echo Environment configured for x64
echo Using ml64 from: %VCToolsInstallDir%bin\Hostx64\x64\

echo Environment configured for x64

REM Create output directories
if not exist "lib" mkdir lib
if not exist "obj" mkdir obj
if not exist "include\kernels" mkdir include\kernels

REM ============================================================================
REM Assemble MASM files
REM ============================================================================
echo.
echo Assembling MASM kernels...

ml64.exe ^
    /c ^
    /Foobj\quantized_matmul.obj ^
    /W3 ^
    /Zi ^
    /Zd ^
    /Cp ^
    /nologo ^
    src\kernels\quantized_matmul.asm

if errorlevel 1 (
    echo ERROR: MASM assembly failed.
    exit /b 1
)

echo [OK] quantized_matmul.asm -> obj\quantized_matmul.obj

REM ============================================================================
REM Create static library
REM ============================================================================
echo.
echo Creating static library...

lib.exe ^
    /OUT:lib\RawrXD_QuantizedKernels.lib ^
    /NOLOGO ^
    /MACHINE:X64 ^
    obj\quantized_matmul.obj

if errorlevel 1 (
    echo ERROR: Library creation failed.
    exit /b 1
)

echo [OK] lib\RawrXD_QuantizedKernels.lib

REM ============================================================================
REM Copy headers
REM ============================================================================
echo.
echo Installing headers...

copy /Y src\kernels\quantized_matmul.hpp include\kernels\ >nul
echo [OK] include\kernels\quantized_matmul.hpp

REM ============================================================================
REM Build test harness (optional)
REM ============================================================================
echo.
echo Building test harness...

cl.exe ^
    /std:c++17 ^
    /O2 ^
    /EHsc ^
    /W4 ^
    /Iinclude ^
    /Iinclude\kernels ^
    /Fe:bin\test_quantized_kernels.exe ^
    src\kernels\test_quantized_kernels.cpp ^
    lib\RawrXD_QuantizedKernels.lib ^
    /link ^
    /MACHINE:X64 ^
    /SUBSYSTEM:CONSOLE

if errorlevel 1 (
    echo WARNING: Test harness build failed (non-fatal).
) else (
    echo [OK] bin\test_quantized_kernels.exe
)

REM ============================================================================
REM Summary
REM ============================================================================
echo.
echo ============================================================================
echo Build Complete
echo ============================================================================
echo.
echo Outputs:
echo   Library: lib\RawrXD_QuantizedKernels.lib
echo   Headers: include\kernels\quantized_matmul.hpp
echo.
echo Kernels Built:
echo   [HOT] QuantizedMatMul_Fused_4K  (4096 dims)
echo   [HOT] QuantizedMatMul_Fused_5K  (5120 dims)
echo   [COLD] QuantizedMatMul_Dynamic (generic)
echo.
echo Performance Targets:
echo   Current: 540 TPS (after Fix #3 NHWC)
echo   Target:  650 TPS (Fix #4 fused kernels)
echo   Gain:    1.20x (20%% improvement)
echo.
echo Next Steps:
echo   1. Run: bin\test_quantized_kernels.exe
echo   2. Integrate with inference engine
echo   3. Benchmark against baseline
echo.

endlocal
