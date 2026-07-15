@echo off
echo ============================================
echo Phase 7C: Build and Run
echo ============================================
cd /d d:\rawrxd

echo Building Phase 7C...
g++ -std=c++17 -O2 -I. -Iinclude RawRamXD_Phase7C_PredictivePrefetch.cpp src\rawramxd\tensor_predictor.cpp src\rawramxd\gpu_fabric.cpp -o build\RawRamXD_Phase7C_PredictivePrefetch.exe -ld3d12 -ldxgi -lpsapi -lkernel32 -ladvapi32 2>&1

if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED
    exit /b 1
)

echo Build successful!
echo.
echo Running benchmark...
build\RawRamXD_Phase7C_PredictivePrefetch.exe

echo.
echo ============================================
echo Benchmark complete
echo ============================================
