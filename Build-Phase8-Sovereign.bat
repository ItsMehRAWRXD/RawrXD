@echo off
echo ============================================
echo Phase 8: Sovereign Integration
echo ============================================
cd /d d:\rawrxd

echo Building Phase 8...
g++ -std=c++17 -O2 -I. -Iinclude ^
    RawRamXD_Phase8_SovereignIntegration.cpp ^
    src\rawramxd\sovereign_integration.cpp ^
    src\rawramxd\tensor_predictor.cpp ^
    src\rawramxd\gpu_fabric.cpp ^
    -o build\RawRamXD_Phase8_SovereignIntegration.exe ^
    -ld3d12 -ldxgi -lpsapi -lkernel32 -ladvapi32

if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED
    exit /b 1
)

echo Build successful!
echo.
echo Running Phase 8 benchmark...
build\RawRamXD_Phase8_SovereignIntegration.exe

echo.
echo ============================================
echo Phase 8 complete
echo ============================================
