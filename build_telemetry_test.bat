@echo off
REM ============================================================================
REM Build SEG Telemetry Pipeline Test (Minimal)
REM ============================================================================

echo ==========================================
echo SEG Telemetry Pipeline Test Build
echo ==========================================
echo.

set SEG_DIR=D:\src\seg
set RUNTIME_DIR=D:\src\runtime
set BUILD_DIR=build_seg

echo [1/1] Compiling telemetry test...
g++ -std=c++17 -O2 -mavx2 -mfma -I. -I./src -I"%SEG_DIR%" -I"%RUNTIME_DIR%" ^
    tests\seg_telemetry_pipeline_test.cpp ^
    src\gateway\seg_gateway.cpp ^
    "%BUILD_DIR%\libseg.a" ^
    -o seg_telemetry_test.exe ^
    -lws2_32

if errorlevel 1 (
    echo FAILED: Compilation failed
    exit /b 1
)

echo      OK: seg_telemetry_test.exe
echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Running test...
echo.
seg_telemetry_test.exe
echo.
