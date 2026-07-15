@echo off
chcp 65001 >nul
echo.
echo ========================================
echo   RawrXD Regression Test Runner
echo ========================================
echo.

setlocal enabledelayedexpansion
set "PASSED=0"
set "FAILED=0"

:: Run regression test executable
echo Running regression tests...
echo.

regression\test_regression.exe
if %ERRORLEVEL% neq 0 (
    echo.
    echo ✗ REGRESSION TESTS FAILED
    exit /b 1
)

echo.
echo ✓ REGRESSION TESTS PASSED
exit /b 0
