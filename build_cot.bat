@echo off
REM ============================================================================
REM Build CoT Multi-Mode Engine + Unified Execution ABI
REM ============================================================================

echo Building RawrXD CLI v4.0 — Unified Execution System...
echo.

set SRC_DIR=src\cot
set CLI_DIR=src\cli
set OUT_DIR=build\cot

if not exist %OUT_DIR% mkdir %OUT_DIR%

REM Compile CoT Engine
echo [1/7] Compiling CoT Multi-Mode Engine...
g++ -std=c++20 -c -I. -Isrc -Ithird_party %SRC_DIR%\cot_multi_mode_engine.cpp -o %OUT_DIR%\cot_multi_mode_engine.obj -O2
if errorlevel 1 goto error

REM Compile Unified Execution ABI
echo [2/7] Compiling Unified Execution ABI...
g++ -std=c++20 -c -I. -Isrc -Ithird_party %CLI_DIR%\unified_execution_abi.cpp -o %OUT_DIR%\unified_execution_abi.obj -O2
if errorlevel 1 goto error

REM Compile CoT Unified Integration
echo [3/7] Compiling CoT Unified Integration...
g++ -std=c++20 -c -I. -Isrc -Ithird_party %CLI_DIR%\cot_unified_integration.cpp -o %OUT_DIR%\cot_unified_integration.obj -O2
if errorlevel 1 goto error

REM Compile CoT Tests
echo [4/7] Compiling CoT Test Suite...
g++ -std=c++20 -c -I. -Isrc -Ithird_party tests\test_cot_multi_mode.cpp -o %OUT_DIR%\test_cot_multi_mode.obj -O2
if errorlevel 1 goto error

REM Compile Unified ABI Tests
echo [5/7] Compiling Unified ABI Test Suite...
g++ -std=c++20 -c -I. -Isrc -Ithird_party tests\test_unified_execution_abi.cpp -o %OUT_DIR%\test_unified_execution_abi.obj -O2
if errorlevel 1 goto error

REM Link CoT Test Executable
echo [6/7] Linking CoT Test Executable...
g++ -std=c++20 %OUT_DIR%\cot_multi_mode_engine.obj %OUT_DIR%\test_cot_multi_mode.obj -o %OUT_DIR%\test_cot_multi_mode.exe -lwininet -lws2_32
if errorlevel 1 goto error

REM Link Unified ABI Test Executable
echo [7/7] Linking Unified ABI Test Executable...
g++ -std=c++20 %OUT_DIR%\unified_execution_abi.obj %OUT_DIR%\test_unified_execution_abi.obj -o %OUT_DIR%\test_unified_execution_abi.exe -lwininet -lws2_32
if errorlevel 1 goto error

echo.
echo ==========================================
echo Build Complete!
echo ==========================================
echo.
echo Run CoT tests with: %OUT_DIR%\test_cot_multi_mode.exe
echo Run Unified ABI tests with: %OUT_DIR%\test_unified_execution_abi.exe
echo.

REM Run CoT tests
echo Running CoT Multi-Mode tests...
%OUT_DIR%\test_cot_multi_mode.exe
if errorlevel 1 goto test_failed

REM Run Unified ABI tests
echo.
echo Running Unified Execution ABI tests...
%OUT_DIR%\test_unified_execution_abi.exe
if errorlevel 1 goto test_failed

echo.
echo ==========================================
echo ALL TESTS PASSED!
echo ==========================================
goto end

:error
echo.
echo ==========================================
echo BUILD FAILED
echo ==========================================
exit /b 1

:test_failed
echo.
echo ==========================================
echo SOME TESTS FAILED
echo ==========================================
exit /b 1

:end
