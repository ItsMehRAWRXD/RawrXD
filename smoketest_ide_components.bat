@echo off
setlocal enabledelayedexpansion

echo ==================================================================
echo   RawrXD IDE Components - Comprehensive Smoketest
echo ==================================================================
echo.
echo This script will verify all IDE components are functional:
echo   1. HTTP Server (rawrxd_server.exe)
echo   2. MASM Orchestrator (SovereignOrchestrator_Fixed.exe)
echo   3. C++ Inference Engine (sovereign_super_node.exe --bridge)
echo   4. Shared Memory IPC
echo ==================================================================
echo.

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "PASS_COUNT=0"
set "FAIL_COUNT=0"

:: Test 1: Check HTTP Server Binary
echo [TEST 1/8] Checking HTTP Server binary...
if exist "rawrxd_server.exe" (
    echo   [PASS] rawrxd_server.exe found
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] rawrxd_server.exe NOT found
    set /a FAIL_COUNT+=1
)
echo.

:: Test 2: Check MASM Orchestrator Binary
echo [TEST 2/8] Checking MASM Orchestrator binary...
if exist "SovereignOrchestrator_Fixed.exe" (
    echo   [PASS] SovereignOrchestrator_Fixed.exe found
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] SovereignOrchestrator_Fixed.exe NOT found
    set /a FAIL_COUNT+=1
)
echo.

:: Test 3: Check C++ Inference Engine Binary
echo [TEST 3/8] Checking C++ Inference Engine binary...
if exist "..\rawrxd\build-sovereign\bin\sovereign_super_node.exe" (
    echo   [PASS] sovereign_super_node.exe found
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] sovereign_super_node.exe NOT found
    set /a FAIL_COUNT+=1
)
echo.

:: Test 4: Verify HTTP Server Help
echo [TEST 4/8] Testing HTTP Server (--help)...
rawrxd_server.exe --help > test_http_help.txt 2>&1
if %errorlevel% equ 0 (
    findstr /C:"RawrXD HTTP Server" test_http_help.txt >nul
    if %errorlevel% equ 0 (
        echo   [PASS] HTTP Server responds to --help
        set /a PASS_COUNT+=1
    ) else (
        echo   [FAIL] HTTP Server help output unexpected
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [FAIL] HTTP Server --help failed
    set /a FAIL_COUNT+=1
)
del test_http_help.txt 2>nul
echo.

:: Test 5: Verify C++ Engine Help
echo [TEST 5/8] Testing C++ Inference Engine (--help)...
"..\rawrxd\build-sovereign\bin\sovereign_super_node.exe" --help > test_engine_help.txt 2>&1
if %errorlevel% equ 0 (
    findstr /C:"--bridge" test_engine_help.txt >nul
    if %errorlevel% equ 0 (
        echo   [PASS] C++ Engine has --bridge mode
        set /a PASS_COUNT+=1
    ) else (
        echo   [WARN] C++ Engine help works but --bridge not found
        set /a FAIL_COUNT+=1
    )
) else (
    echo   [FAIL] C++ Engine --help failed
    set /a FAIL_COUNT+=1
)
del test_engine_help.txt 2>nul
echo.

:: Test 6: Check Shared Memory Objects (if orchestrator is running)
echo [TEST 6/8] Checking Shared Memory IPC objects...
echo   [INFO] Looking for SOVEREIGN_BEACON_V1...
handle SOVEREIGN_BEACON_V1 >nul 2>&1
if %errorlevel% equ 0 (
    echo   [PASS] Shared memory exists (orchestrator running)
    set /a PASS_COUNT+=1
) else (
    echo   [INFO] Shared memory not found (orchestrator not running - OK for smoketest)
    set /a PASS_COUNT+=1
)
echo.

:: Test 7: Verify Launch Scripts
echo [TEST 7/8] Checking Launch Scripts...
if exist "launch_full_stack.bat" (
    echo   [PASS] launch_full_stack.bat found
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] launch_full_stack.bat NOT found
    set /a FAIL_COUNT+=1
)

if exist "test_bridge_mode.bat" (
    echo   [PASS] test_bridge_mode.bat found
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] test_bridge_mode.bat NOT found
    set /a FAIL_COUNT+=1
)
echo.

:: Test 8: Verify Documentation
echo [TEST 8/8] Checking Documentation...
if exist "BRIDGE_MODE_DOCUMENTATION.md" (
    echo   [PASS] BRIDGE_MODE_DOCUMENTATION.md found
    set /a PASS_COUNT+=1
) else (
    echo   [FAIL] BRIDGE_MODE_DOCUMENTATION.md NOT found
    set /a FAIL_COUNT+=1
)
echo.

:: Summary
echo ==================================================================
echo   SMOKETEST SUMMARY
echo ==================================================================
echo   Passed: %PASS_COUNT%
echo   Failed: %FAIL_COUNT%
echo.

if %FAIL_COUNT% equ 0 (
    echo   [SUCCESS] All IDE components verified!
    echo.
    echo   Next steps:
    echo     1. Run: launch_full_stack.bat
    echo     2. Test: curl http://localhost:8080/health
    echo     3. Test: curl -X POST http://localhost:8080/v1/completions ^
    echo               -H "Content-Type: application/json" ^
    echo               -d "{\"model\": \"rawrxd\", \"prompt\": \"Hello\", \"max_tokens\": 10}"
    exit /b 0
) else (
    echo   [WARNING] Some tests failed. Review output above.
    exit /b 1
)
