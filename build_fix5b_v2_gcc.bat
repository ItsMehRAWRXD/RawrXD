@echo off
REM Build script for Fix #5B Phase 2: Page-Based Async KV Cache Residency Validation
REM Using GCC since MSVC cl.exe is not available

setlocal EnableDelayedExpansion

echo ============================================
echo Fix #5B Phase 2 Residency Validation Build
echo ============================================
echo.

REM Set up paths
set "SOURCE_DIR=%~dp0"
set "BUILD_DIR=%SOURCE_DIR%build-fix5b-residency"
set "SRC_MEMORY=%SOURCE_DIR%src\memory"
set "TESTS_DIR=%SOURCE_DIR%tests"

REM Check for GCC
where gcc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: GCC not found in PATH
    exit /b 1
)

echo Found GCC compiler

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo ============================================
echo Compiling Fix #5B Residency Tests
echo ============================================
echo.

REM Compiler flags
set "CXXFLAGS=-std=c++17 -Wall -O3 -mavx2 -mfma -I"%SOURCE_DIR%src" -I"%SOURCE_DIR%include" -I"%SOURCE_DIR%src\memory" -D_CRT_SECURE_NO_WARNINGS -DNOMINMAX"

REM Source files for the test
set "SOURCES="
set "SOURCES=%SOURCES% "%TESTS_DIR%\test_fix5b_residency_v2.cpp""
set "SOURCES=%SOURCES% "%SRC_MEMORY%\RawrXD_KVCache_Residency_v2.cpp""
set "SOURCES=%SOURCES% "%SRC_MEMORY%\RawrXD_KVCache_QuantKernels.cpp""

REM Benchmark source
set "BENCH_SOURCES="
set "BENCH_SOURCES=%BENCH_SOURCES% "%TESTS_DIR%\benchmark_quant_kernels.cpp""
set "BENCH_SOURCES=%BENCH_SOURCES% "%SRC_MEMORY%\RawrXD_KVCache_QuantKernels.cpp""

REM Output executable
set "OUTPUT=%BUILD_DIR%\test_fix5b_residency_v2.exe"

echo Compiling...
echo Sources: %SOURCES%
echo Output: %OUTPUT%
echo.

g++.exe %CXXFLAGS% %SOURCES% -o "%OUTPUT%"

if %ERRORLEVEL% neq 0 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Executable: %OUTPUT%
echo.
echo Running validation tests...
echo.

"%OUTPUT%"

set "TEST_RESULT=%ERRORLEVEL%"

if %TEST_RESULT% equ 0 (
    echo.
    echo ============================================
    echo ALL VALIDATION TESTS PASSED
    echo ============================================
    echo.
    echo Building benchmark...
    echo.
    
    REM Build benchmark
    set "BENCH_OUTPUT=%BUILD_DIR%\benchmark_quant_kernels.exe"
    g++.exe %CXXFLAGS% %BENCH_SOURCES% -o "%BENCH_OUTPUT%"
    
    if %ERRORLEVEL% equ 0 (
        echo Running benchmark...
        echo.
        "%BENCH_OUTPUT%" 16 5
    ) else (
        echo Benchmark build failed, but validation tests passed.
    )
    
    echo.
    echo ============================================
    echo FIX 5B PHASE 2 COMPLETE
    echo ============================================
    echo.
    echo Implementation includes:
    echo   - Page-based async residency management
    echo   - Quantization kernels (Q8_0, Q4_0, Q4_K, Q2_K)
    echo   - SIMD optimizations (AVX2)
    echo   - Comprehensive validation framework
    echo.
) else (
    echo.
    echo ============================================
    echo VALIDATION TESTS FAILED (exit code: %TEST_RESULT%)
    echo ============================================
    echo.
    echo Please review the errors above.
)

exit /b %TEST_RESULT%
