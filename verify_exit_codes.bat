@echo off
REM Verify CLI exit codes are working correctly

echo === Verifying Step A: Exit Code Contract ===
echo.

REM Test 1: Help returns 0
rawrxd_v2.exe help > nul 2>&1
if %errorlevel% equ 0 (
    echo [PASS] Help command returns exit code 0
) else (
    echo [FAIL] Help command returned %errorlevel%
)

REM Test 2: Unknown command returns 1
rawrxd_v2.exe unknowncommand > nul 2>&1
if %errorlevel% equ 1 (
    echo [PASS] Unknown command returns exit code 1
) else (
    echo [FAIL] Unknown command returned %errorlevel%
)

REM Test 3: Missing required flag returns 1
rawrxd_v2.exe run --prompt "test" > nul 2>&1
if %errorlevel% equ 1 (
    echo [PASS] Missing flag returns exit code 1
) else (
    echo [FAIL] Missing flag returned %errorlevel%
)

REM Test 4: Missing file returns 1
rawrxd_v2.exe inspect nonexistent.gguf > nul 2>&1
if %errorlevel% equ 1 (
    echo [PASS] Missing file returns exit code 1
) else (
    echo [FAIL] Missing file returned %errorlevel%
)

REM Test 5: Kernel list returns 0
rawrxd_v2.exe kernel --list > nul 2>&1
if %errorlevel% equ 0 (
    echo [PASS] Kernel list returns exit code 0
) else (
    echo [FAIL] Kernel list returned %errorlevel%
)

echo.
echo === Step A Verification Complete ===
