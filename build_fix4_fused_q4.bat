@echo off
REM ============================================================================
REM Fix #4 Build Script: Fused Q4_0 Kernels
REM Target: 650 TPS (1.2-1.3x gain)
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set RAWRXD_ROOT=D:\RawrXD
set BUILD_DIR=%RAWXD_ROOT%\build_fix4
set ML64_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe

echo ============================================================================
echo Fix #4: Fused Q4_0 Kernel Build
echo ============================================================================
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Check for AVX-512 assembler
echo [1/4] Assembling AVX-512 kernel...
"%ML64_PATH%" /c /Fo"%BUILD_DIR%\quantized_matmul_fused_q4.obj" ^
    "%RAWXD_ROOT%\src\kernels\quantized_matmul_fused_q4.asm"

if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)
echo     OK: quantized_matmul_fused_q4.obj

REM Compile C++ wrapper
echo.
echo [2/4] Compiling C++ wrapper...
"%CL_PATH%" /c /O2 /arch:AVX512 /EHsc /std:c++20 /I"%RAWXD_ROOT%\src" ^
    /Fo"%BUILD_DIR%\RawrXD_FusedQ4_Kernel.obj" ^
    "%RAWXD_ROOT%\src\kernels\RawrXD_FusedQ4_Kernel.cpp"

if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)
echo     OK: RawrXD_FusedQ4_Kernel.obj

REM Create static library
echo.
echo [3/4] Creating library...
lib /OUT:"%BUILD_DIR%\RawrXD_Fix4.lib" ^
    "%BUILD_DIR%\quantized_matmul_fused_q4.obj" ^
    "%BUILD_DIR%\RawrXD_FusedQ4_Kernel.obj"

if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)
echo     OK: RawrXD_Fix4.lib

REM Build test executable
echo.
echo [4/4] Building test harness...
"%CL_PATH%" /O2 /arch:AVX512 /EHsc /std:c++20 /I"%RAWXD_ROOT%\src" ^
    "%RAWXD_ROOT%\tests\test_fused_q4_kernel.cpp" ^
    "%BUILD_DIR%\RawrXD_Fix4.lib" ^
    /Fe"%BUILD_DIR%\test_fused_q4.exe"

if errorlevel 1 (
    echo ERROR: Test build failed
    exit /b 1
)
echo     OK: test_fused_q4.exe

echo.
echo ============================================================================
echo Fix #4 Build Complete
echo ============================================================================
echo.
echo Artifacts:
echo   %BUILD_DIR%\RawrXD_Fix4.lib
echo   %BUILD_DIR%\test_fused_q4.exe
echo.
echo Next steps:
echo   1. Run: %BUILD_DIR%\test_fused_q4.exe
echo   2. Verify TPS improvement: 540 -^> 650 TPS
echo   3. Profile with: perf stat -e cycles,instructions,cache-misses
echo.

endlocal
