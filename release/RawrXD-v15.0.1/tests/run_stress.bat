@echo off
chcp 65001 >nul
echo.
echo ========================================
echo   RawrXD Stress Test Runner
echo ========================================
echo.

setlocal enabledelayedexpansion
set "PASSED=0"
set "FAILED=0"

:: Run stress test executable
echo Running stress tests...
echo.

stress\test_stress_kernels.exe
if %ERRORLEVEL% neq 0 (
    echo.
    echo ✗ STRESS TESTS FAILED
    exit /b 1
)

echo.
echo ✓ STRESS TESTS PASSED
exit /b 0
