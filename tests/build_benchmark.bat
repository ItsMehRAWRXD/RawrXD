@echo off
REM Phase 20: Standalone Benchmark Build Script
REM Bypasses CMake integration debt, builds minimal benchmark harness
REM Requires: ml64.exe (MASM) and g++ (MinGW)

setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD Phase 20: Standalone Benchmark Build
echo ============================================
echo.

REM Configuration
set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717"
set "MASM_PATH=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "CXX_PATH=C:\ProgramData\mingw64\mingw64\bin\g++.exe"
set "SRC_DIR=%~dp0..\src"
set "TEST_DIR=%~dp0"
set "BUILD_DIR=%~dp0..\build-benchmark"

REM Check for ml64.exe
if not exist "%MASM_PATH%" (
    echo ERROR: ml64.exe not found at %MASM_PATH%
    echo Please update VS_TOOLS in this script or ensure VS2022 is installed
    exit /b 1
)

REM Check for g++
if not exist "%CXX_PATH%" (
    echo ERROR: g++.exe not found at %CXX_PATH%
    echo Please install MinGW or update CXX_PATH
    exit /b 1
)

echo MASM: %MASM_PATH%
echo CXX:  %CXX_PATH%
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Step 1: Assemble the optimized kernel
echo [1/4] Assembling ApplyLoRA_Optimized.asm...
"%MASM_PATH%" /c /Fo"%BUILD_DIR%\ApplyLoRA_Optimized.obj" /W3 /Zd /Zi ^
    /I"%SRC_DIR%\include" ^
    "%SRC_DIR%\fusion\kernels\ApplyLoRA_Optimized.asm" 2>&1

if errorlevel 1 (
    echo ERROR: Failed to assemble ApplyLoRA_Optimized.asm
    exit /b 1
)

echo     OK: %BUILD_DIR%\ApplyLoRA_Optimized.obj
echo.

REM Step 2: Assemble the baseline kernel
echo [2/4] Assembling ApplyLoRA_Baseline (from optimized file)...
"%MASM_PATH%" /c /Fo"%BUILD_DIR%\ApplyLoRA_Baseline.obj" /W3 /Zd /Zi ^
    /I"%SRC_DIR%\include" ^
    "%SRC_DIR%\fusion\kernels\ApplyLoRA_Optimized.asm" 2>&1

if errorlevel 1 (
    echo ERROR: Failed to assemble baseline
    exit /b 1
)

echo     OK: %BUILD_DIR%\ApplyLoRA_Baseline.obj
echo.

REM Step 3: Compile TSCMonitor (from Phase 19)
echo [3/4] Compiling TSCMonitor.cpp...
"%CXX_PATH%" -c -O3 -mavx512f -mavx512vl -o "%BUILD_DIR%\TSCMonitor.o" ^
    -I"%SRC_DIR%" ^
    -D_CRT_SECURE_NO_WARNINGS ^
    "%SRC_DIR%\tests\TSCMonitor.cpp" 2>&1

if errorlevel 1 (
    echo ERROR: Failed to compile TSCMonitor.cpp
    exit /b 1
)

echo     OK: %BUILD_DIR%\TSCMonitor.o
echo.

REM Step 4: Compile and link benchmark
echo [4/4] Building benchmark_kernel.exe...
"%CXX_PATH%" -O3 -mavx512f -mavx512vl -o "%BUILD_DIR%\benchmark_kernel.exe" ^
    -I"%SRC_DIR%" ^
    -D_CRT_SECURE_NO_WARNINGS ^
    "%TEST_DIR%\benchmark_kernel.cpp" ^
    "%BUILD_DIR%\TSCMonitor.o" ^
    "%BUILD_DIR%\ApplyLoRA_Optimized.obj" ^
    -static-libgcc -static-libstdc++ 2>&1

if errorlevel 1 (
    echo ERROR: Failed to build benchmark
    exit /b 1
)

echo     OK: %BUILD_DIR%\benchmark_kernel.exe
echo.

REM Success
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo To run the benchmark:
echo   %BUILD_DIR%\benchmark_kernel.exe [test_size] [rank]
echo.
echo Examples:
echo   %BUILD_DIR%\benchmark_kernel.exe              :: Default: 1M elements, rank 8
echo   %BUILD_DIR%\benchmark_kernel.exe 2097152 16  :: 2M elements, rank 16
echo   %BUILD_DIR%\benchmark_kernel.exe 524288 4   :: 512K elements, rank 4
echo.
echo Target: P95 latency ^< 42M cycles (~10ms @ 4.2GHz)
echo.

endlocal
