@echo off
chcp 65001 > nul
echo ============================================
echo RawRamXD Phase 8: Sovereign Integration
echo Inference Loop Integration Test
echo ============================================
echo.

set SOURCE=RawRamXD_Phase8_SovereignIntegration.cpp
set SOVEREIGN_SRC=src\rawramxd\sovereign_integration.cpp
set PREDICTOR_SRC=src\rawramxd\tensor_predictor.cpp
set FABRIC_SRC=src\rawramxd\gpu_fabric.cpp
set OUTPUT=build\RawRamXD_Phase8_SovereignIntegration.exe

if not exist build mkdir build

echo Building Phase 8 Sovereign Integration...
echo.

g++ -std=c++17 -O2 -g -Wall -Wextra -I. -Iinclude -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_AMD64_ -DNDEBUG %SOURCE% %SOVEREIGN_SRC% %PREDICTOR_SRC% %FABRIC_SRC% -o %OUTPUT% -ld3d12 -ldxgi -lpsapi -lkernel32 -ladvapi32 -lgdi32 -luser32 -lsynchronization

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
echo Running Sovereign Integration test...
echo This validates predictive prefetch in inference loop.
echo.

%OUTPUT%

if %ERRORLEVEL% neq 0 (
    echo.
    echo Test failed with error code %ERRORLEVEL%
    exit /b 1
)

echo.
echo ============================================
echo TEST COMPLETE
echo ============================================
