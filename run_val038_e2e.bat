@echo off
:: Run script for VAL-038 E2E Integration Test
:: Executes the live-fire validation: Cold-start -> Hot-patch -> Inference -> Hash validation

echo ==========================================
echo VAL-038 E2E Integration Test Runner
echo ==========================================
echo.

:: Check if executable exists
if not exist build_fix3\bin\SovereignTest_VAL038_E2E.exe (
    echo [ERROR] Executable not found: build_fix3\bin\SovereignTest_VAL038_E2E.exe
    echo Run build_val038_e2e.bat first
    exit /b 1
)

:: Run the E2E test
echo [EXEC] Running VAL-038 E2E test...
echo.
build_fix3\bin\SovereignTest_VAL038_E2E.exe
set EXITCODE=%ERRORLEVEL%

echo.
echo ==========================================
if %EXITCODE% equ 0 (
    echo [PASS] VAL-038 E2E test PASSED
    echo The Nightmare patch is production-ready
) else (
    echo [FAIL] VAL-038 E2E test FAILED (exit code: %EXITCODE%)
    echo Review output above for failure details
)
echo ==========================================

exit /b %EXITCODE%
