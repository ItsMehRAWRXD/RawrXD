@echo off
:: ============================================================================
:: RawrXD No-Dependencies Build Script
:: ============================================================================
:: Builds the complete inference pipeline with zero external dependencies
:: Uses only: Windows SDK, MSVC/GCC, and the source files in this repo
:: ============================================================================

setlocal EnableDelayedExpansion

echo ========================================
echo RawrXD No-Dependencies Build
echo ========================================
echo.

:: Configuration
set BUILD_DIR=build_no_deps
set SRC_DIR=src
set CORE_DIR=%SRC_DIR%\core
set INFERENCE_DIR=%SRC_DIR%\inference
set RUNTIME_DIR=..\src\runtime
set KERNELS_DIR=%SRC_DIR%\kernels

:: Detect compiler
where cl > nul 2>&1
if %errorlevel% == 0 (
    set COMPILER=msvc
    echo Using MSVC compiler
) else (
    where gcc > nul 2>&1
    if %errorlevel% == 0 (
        set COMPILER=gcc
        echo Using GCC compiler
    ) else (
        echo ERROR: No compiler found. Please install MSVC or GCC.
        exit /b 1
    )
)

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd %BUILD_DIR%

echo.
echo Building core components...
echo.

:: Source files
set CORE_SRCS=^
    ..\%CORE_DIR%\minimal_json.cpp^
    ..\%CORE_DIR%\streaming_loader.cpp^
    ..\%INFERENCE_DIR%\unified_inference.cpp^
    ..\%RUNTIME_DIR%\kv_cache_optimized.cpp^
    ..\%RUNTIME_DIR%\transformer_layer_optimized.cpp^
    ..\%KERNELS_DIR%\avx2_kernels.cpp^
    ..\%KERNELS_DIR%\avx512_kernels.cpp

set TEST_SRCS=..<%SRC_DIR%\tests\test_unified_inference.cpp

:: Compiler flags
if "%COMPILER%"=="msvc" (
    set CFLAGS=/std:c++17 /O2 /arch:AVX2 /EHsc /W3 /nologo^
        /I..\%SRC_DIR% /I..\%CORE_DIR% /I..\%INFERENCE_DIR%^
        /I..\%RUNTIME_DIR% /I..\%KERNELS_DIR%^
        /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN
    
    set LDFLAGS=/link /MACHINE:X64 kernel32.lib user32.lib
    
    :: Build library
    echo Building core library...
    cl /c %CFLAGS% %CORE_SRCS%
    if errorlevel 1 goto :error
    
    :: Build test
    echo Building test executable...
    cl %CFLAGS% %TEST_SRCS% *.obj %LDFLAGS% /OUT:test_unified_inference.exe
    if errorlevel 1 goto :error
    
) else (
    set CFLAGS=-std=c++17 -O3 -mavx2 -mfma -mavx512f -mavx512dq^
        -I..\%SRC_DIR% -I..\%CORE_DIR% -I..\%INFERENCE_DIR%^
        -I..\%RUNTIME_DIR% -I..\%KERNELS_DIR%^
        -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN
    
    set LDFLAGS=-lkernel32 -luser32
    
    :: Build test
    echo Building test executable...
    g++ %CFLAGS% %CORE_SRCS% %TEST_SRCS% %LDFLAGS% -o test_unified_inference.exe
    if errorlevel 1 goto :error
)

echo.
echo ========================================
echo Build Successful!
echo ========================================
echo.
echo Executables:
echo   - test_unified_inference.exe
echo.
echo To run tests:
echo   test_unified_inference.exe [model.gguf]
echo.
echo No external dependencies required!
echo.

cd ..
exit /b 0

:error
echo.
echo ========================================
echo Build Failed!
echo ========================================
cd ..
exit /b 1
