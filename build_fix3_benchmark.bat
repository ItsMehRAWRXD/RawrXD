@echo off
REM ============================================================================
REM Fix #3 NHWC Layout Validation Build Script
REM Builds and runs the comprehensive benchmark suite
REM ============================================================================

setlocal EnableDelayedExpansion

echo ============================================================================
echo Fix #3 NHWC Layout - Validation Build
echo ============================================================================
echo.

REM Visual Studio 2022 path (detected from system)
set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231
set CL_EXE="%VS_PATH%\bin\Hostx64\x64\cl.exe"

REM Verify compiler exists
if not exist %CL_EXE% (
    echo ERROR: cl.exe not found at %CL_EXE%
    echo Please verify Visual Studio 2022 installation
    exit /b 1
)

echo [0/3] Using compiler: %CL_EXE%
echo.

REM Directories
set SRC_DIR=d:\RawrXD\src\benchmark
set MEMORY_DIR=d:\RawrXD\src\memory
set OBJ_DIR=d:\RawrXD\obj\benchmark
set BIN_DIR=d:\RawrXD\bin

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %BIN_DIR% mkdir %BIN_DIR%

echo [1/3] Building Fix3_NHWC_Benchmark.cpp...
echo.

%CL_EXE% /nologo /W4 /EHsc /O2 /Zi /MD /arch:AVX512 /Fe"%BIN_DIR%\Fix3_NHWC_Benchmark.exe" ^
    "%SRC_DIR%\Fix3_NHWC_Benchmark.cpp" ^
    /I"%MEMORY_DIR%" ^
    /I"d:\RawrXD\include" ^
    2>&1

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo         Fix3_NHWC_Benchmark.exe - OK
echo.

echo [2/3] Running validation benchmark...
echo.

%BIN_DIR%\Fix3_NHWC_Benchmark.exe > "%OBJ_DIR%\benchmark_results.txt" 2>&1

if errorlevel 1 (
    echo ERROR: Benchmark failed
    type "%OBJ_DIR%\benchmark_results.txt"
    exit /b 1
)

type "%OBJ_DIR%\benchmark_results.txt"
echo.

echo [3/3] Saving results...
echo.

copy /Y "%OBJ_DIR%\benchmark_results.txt" "d:\RawrXD\FIX3_NHWC_BENCHMARK_RESULTS.txt" >nul

echo ============================================================================
echo Validation Complete
echo ============================================================================
echo.
echo Results saved to: FIX3_NHWC_BENCHMARK_RESULTS.txt
echo.
echo Next steps:
echo   1. Review benchmark results above
echo   2. Verify speedup meets 1.5x target
echo   3. Proceed to Fix #4 (Fused Q4_0 Kernels)
echo.

endlocal
