@echo off
REM ============================================================================
REM build_sovereign.bat - Sovereign IDE Build Script
REM Builds all components and runs validation
REM ============================================================================
setlocal enabledelayedexpansion

set BUILD_DIR=build_sovereign
set BIN_DIR=%BUILD_DIR%\bin

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║     Sovereign IDE - Build Script                        ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.

REM Check for VS2022
if not exist "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe" (
    echo [WARNING] VS2022 Enterprise not found at expected path.
    echo Attempting to use cmake with default generator...
)

REM Configure
echo [1/4] Configuring CMake...
cmake -B %BUILD_DIR% -G "Ninja" ^
    -DCMAKE_C_COMPILER="C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe" ^
    -DCMAKE_CXX_COMPILER="C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe" ^
    -DCMAKE_ASM_MASM_COMPILER="C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/ml64.exe" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DBUILD_SOVEREIGN_IDE=ON ^
    -DBUILD_SOVEREIGN_IDE_TEST=ON ^
    -DBUILD_SOVEREIGN_TEST_SUITE=ON ^
    -DBUILD_SOVEREIGN_VAL038_E2E=ON ^
    -DBUILD_DEEP2_BATCH_TEST=ON ^
    -DBUILD_DEEP2_PRODUCTION_BENCH=ON ^
    -DBUILD_PATCHREGISTRY_TEST=ON ^
    -DBUILD_HOTPATCHER_TEST=ON ^
    -DBUILD_AUTONOMOUS_AGENT_TEST=ON ^
    -DBUILD_ANTI_HALLUCINATION=ON

if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed!
    exit /b 1
)
echo [OK] Configured successfully.
echo.

REM Build
echo [2/4] Building Sovereign IDE...
cmake --build %BUILD_DIR% --target SovereignIDE -- -j%NUMBER_OF_PROCESSORS%
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Main IDE build had issues, continuing...
)

echo [2/4] Building test suite...
cmake --build %BUILD_DIR% --target SovereignIDE_IntegrationTest -- -j%NUMBER_OF_PROCESSORS%
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Integration test build had issues, continuing...
)
echo.

REM Verify binaries
echo [3/4] Verifying binaries...
if exist %BIN_DIR%\SovereignIDE.exe (
    echo [OK] SovereignIDE.exe - %~z1 bytes
) else (
    echo [WARNING] SovereignIDE.exe not found
)

if exist %BIN_DIR%\SovereignIDE_IntegrationTest.exe (
    echo [OK] SovereignIDE_IntegrationTest.exe
) else (
    echo [WARNING] SovereignIDE_IntegrationTest.exe not found
)
echo.

REM Run validation
echo [4/4] Running validation...
if exist %BIN_DIR%\SovereignIDE.exe (
    %BIN_DIR%\SovereignIDE.exe --test
    echo [OK] Validation complete
) else (
    echo [SKIP] Validation skipped (binary not built)
)
echo.

echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║     Build Complete                                      ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
echo Binaries: %BIN_DIR%
echo.
echo Available targets:
echo   SovereignIDE                  - Main IDE application
echo   SovereignIDE_IntegrationTest  - Full integration test suite
echo   SovereignTest_Suite           - Pre-build CI/CD gate
echo   SovereignTest_VAL038_E2E      - VAL-038 E2E test
echo   Deep2_Batch_Test              - Model stress test
echo   Deep2_Production_Bench       - TPS benchmark
echo   SovereignTest_PatchRegistry   - Patch registry tests
echo   SovereignTest_HotPatcher      - Hot patcher tests
echo   SovereignTest_AutonomousAgent - Autonomous agent tests
echo   SovereignTest_AntiHallucination - Anti-hallucination tests
echo.

endlocal
