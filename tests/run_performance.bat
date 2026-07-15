@echo off
chcp 65001 >nul
echo.
echo ========================================
echo   RawrXD Performance Test Runner
echo ========================================
echo.

setlocal enabledelayedexpansion
set "PASSED=0"
set "FAILED=0"

:: Run performance test executable
echo Running performance benchmarks...
echo.

performance\perf_matmul.exe
if %ERRORLEVEL% neq 0 (
    echo.
    echo ✗ PERFORMANCE TESTS FAILED
    exit /b 1
)

echo.
echo ✓ PERFORMANCE TESTS PASSED
exit /b 0
