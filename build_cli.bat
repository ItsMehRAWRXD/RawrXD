@echo off
:: ============================================================================
:: RawrXD CLI and API Server Build Script
:: ============================================================================

setlocal EnableDelayedExpansion

echo ========================================
echo RawrXD CLI and API Server Build
echo ========================================
echo.

:: Configuration
set BUILD_DIR=build_cli
set CORE_DIR=src\core
set INFERENCE_DIR=src\inference
set RUNTIME_DIR=..\src\runtime
set KERNELS_DIR=src\kernels
set CLI_DIR=src\cli
set API_DIR=src\api

:: Detect compiler
where g++ > nul 2>&1
if %errorlevel% == 0 (
    set COMPILER=gcc
    echo Using GCC compiler
) else (
    echo ERROR: GCC not found. Please install MinGW-w64.
    exit /b 1
)

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd %BUILD_DIR%

echo.
echo Building components...
echo.

:: Compiler flags
set CFLAGS=-std=c++17 -O3 -mavx2 -mfma -mavx512f -mavx512dq^
    -I..\src -I..\src\core -I..\src\inference -I..\%RUNTIME_DIR% -I..\src\kernels^
    -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN

set LDFLAGS=-lkernel32 -luser32 -lwinhttp

:: Source files
set CORE_SRCS=^
    ..\%CORE_DIR%\minimal_json.cpp^
    ..\%CORE_DIR%\streaming_loader.cpp^
    ..\%INFERENCE_DIR%\unified_inference.cpp^
    ..\%RUNTIME_DIR%\kv_cache_optimized.cpp^
    ..\%RUNTIME_DIR%\transformer_layer_optimized.cpp^
    ..\%KERNELS_DIR%\avx2_kernels.cpp^
    ..\%KERNELS_DIR%\avx512_kernels.cpp

:: Build CLI tool
echo Building rawrxd-infer.exe...
g++ %CFLAGS% %CORE_SRCS% ..\%CLI_DIR%\rawrxd_infer.cpp -o rawrxd-infer.exe %LDFLAGS%
if errorlevel 1 goto :error

:: Build API server
echo Building rawrxd-server.exe...
g++ %CFLAGS% %CORE_SRCS% ..\%API_DIR%\openai_compatible_server.cpp -o rawrxd-server.exe %LDFLAGS%
if errorlevel 1 goto :error

echo.
echo ========================================
echo Build Successful!
echo ========================================
echo.
echo Executables:
echo   - rawrxd-infer.exe   (CLI tool)
echo   - rawrxd-server.exe  (OpenAI-compatible API server)
echo.
echo Examples:
echo   rawrxd-infer.exe -m model.gguf -p "Hello world"
echo   rawrxd-infer.exe -m model.gguf --interactive
echo   rawrxd-server.exe model.gguf 8080
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
