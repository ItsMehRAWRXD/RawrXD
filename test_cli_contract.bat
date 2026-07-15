@echo off
REM Test script for RawrXD CLI v2 - Contract Verification
REM Tests: exit codes, JSON output, argument validation

setlocal enabledelayedexpansion

set CLI=.\rawrxd_v2.exe
set PASS=0
set FAIL=0

echo ==========================================
echo RawrXD CLI v2 Contract Tests
echo ==========================================
echo.

REM Test 1: Help returns exit code 0
echo Test 1: Help command (exit code 0)
%CLI% help > nul 2>&1
if %errorlevel% equ 0 (
    echo   PASS: Exit code 0
    set /a PASS+=1
) else (
    echo   FAIL: Expected exit code 0, got %errorlevel%
    set /a FAIL+=1
)
echo.

REM Test 2: Unknown command returns exit code 1
echo Test 2: Unknown command (exit code 1)
%CLI% unknowncommand > nul 2>&1
if %errorlevel% equ 1 (
    echo   PASS: Exit code 1
    set /a PASS+=1
) else (
    echo   FAIL: Expected exit code 1, got %errorlevel%
    set /a FAIL+=1
)
echo.

REM Test 3: Missing required flag returns exit code 1
echo Test 3: Missing required flag (exit code 1)
%CLI% run --prompt "test" > nul 2>&1
if %errorlevel% equ 1 (
    echo   PASS: Exit code 1
    set /a PASS+=1
) else (
    echo   FAIL: Expected exit code 1, got %errorlevel%
    set /a FAIL+=1
)
echo.

REM Test 4: Missing file returns exit code 1
echo Test 4: Missing file (exit code 1)
%CLI% inspect nonexistent.gguf > nul 2>&1
if %errorlevel% equ 1 (
    echo   PASS: Exit code 1
    set /a PASS+=1
) else (
    echo   FAIL: Expected exit code 1, got %errorlevel%
    set /a FAIL+=1
)
echo.

REM Test 5: Successful command returns exit code 0
echo Test 5: Kernel list (exit code 0)
%CLI% kernel --list > nul 2>&1
if %errorlevel% equ 0 (
    echo   PASS: Exit code 0
    set /a PASS+=1
) else (
    echo   FAIL: Expected exit code 0, got %errorlevel%
    set /a FAIL+=1
)
echo.

REM Test 6: JSON output produces valid JSON
echo Test 6: JSON output mode
%CLI% kernel --list --json > test_output.json 2>&1
findstr "command" test_output.json > nul
if %errorlevel% equ 0 (
    echo   PASS: JSON output contains expected fields
    set /a PASS+=1
) else (
    echo   FAIL: JSON output missing expected fields
    set /a FAIL+=1
)
del test_output.json 2> nul
echo.

REM Test 7: Quiet mode suppresses output
echo Test 7: Quiet mode
%CLI% kernel --list --quiet > test_quiet.txt 2>&1
for %%F in (test_quiet.txt) do set size=%%~zF
if %size% equ 0 (
    echo   PASS: Quiet mode suppresses output
    set /a PASS+=1
) else (
    echo   FAIL: Quiet mode produced output
    set /a FAIL+=1
)
del test_quiet.txt 2> nul
echo.

REM Test 8: Test all returns exit code 0
echo Test 8: Test all (exit code 0)
%CLI% test --all > nul 2>&1
if %errorlevel% equ 0 (
    echo   PASS: Exit code 0
    set /a PASS+=1
) else (
    echo   FAIL: Expected exit code 0, got %errorlevel%
    set /a FAIL+=1
)
echo.

REM Summary
echo ==========================================
echo Test Summary
echo ==========================================
echo Passed: %PASS%
echo Failed: %FAIL%
echo Total:  %PASS% + %FAIL%
echo.

if %FAIL% equ 0 (
    echo All tests passed!
    exit /b 0
) else (
    echo Some tests failed.
    exit /b 1
)
