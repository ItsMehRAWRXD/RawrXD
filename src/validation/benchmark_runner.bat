@echo off
REM Performance benchmark runner for RawrXD
REM Runs performance tests and compares against baselines

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Performance Benchmark Runner
echo ==========================================
echo.

set VALIDATOR=..\..\build-validation\rawrxd_validate.exe
set MODEL=%1
set BASELINE=%2

if not exist %VALIDATOR% (
    echo ERROR: Validator not found. Run build_validate.bat first.
    exit /b 1
)

if "%MODEL%"=="" (
    echo ERROR: No model specified
    echo Usage: benchmark_runner.bat ^<model.gguf^> [baseline.json]
    exit /b 1
)

if not exist "%MODEL%" (
    echo ERROR: Model not found: %MODEL%
    exit /b 1
)

echo Model: %MODEL%
if defined BASELINE (
    echo Baseline: %BASELINE%
) else (
    echo Baseline: (none - will create new)
)
echo.

set TIMESTAMP=%date:~10,4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set REPORT=benchmark_%TIMESTAMP%

echo Running benchmarks...
%VALIDATOR% -m "%MODEL%" -o "%REPORT%" --benchmark

echo.
echo Benchmark complete!
echo Report: %REPORT%.json

if defined BASELINE (
    echo.
    echo Comparing with baseline...
    python compare_benchmarks.py %REPORT%.json %BASELINE%
)

exit /b 0
