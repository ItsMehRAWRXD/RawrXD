@echo off
REM ============================================================================
REM Build SEG Integration Test
REM ============================================================================

echo ==========================================
echo SEG Integration Test Build
echo ==========================================
echo.

set SEG_DIR=D:\src\seg
set RUNTIME_DIR=D:\src\runtime
set BUILD_DIR=build_seg

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/2] Compiling test...
g++ -std=c++17 -O2 -mavx2 -mfma -I. -I./src -I./kernels -I"%SEG_DIR%" -I"%RUNTIME_DIR%" ^
    tests\seg_integration_test.cpp ^
    src\gateway\seg_gateway.cpp ^
    src\runtime\tokenizer_runtime.cpp ^
    src\model\model_context.cpp ^
    "%BUILD_DIR%\libseg.a" ^
    -o seg_integration_test.exe ^
    -lws2_32

if errorlevel 1 (
    echo FAILED: Compilation failed
    exit /b 1
)

echo      OK: seg_integration_test.exe
echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Usage:
echo   seg_integration_test.exe [model.gguf] ["prompt"] [max_tokens]
echo.
echo Example:
echo   seg_integration_test.exe test.gguf "Hello" 5
echo.
