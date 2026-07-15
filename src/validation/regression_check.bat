@echo off
REM Regression check script for RawrXD
REM Compares current validation results against stored baselines

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Regression Check
echo ==========================================
echo.

set CURRENT=%1
set BASELINE=%2

if "%CURRENT%"=="" (
    echo ERROR: No current results specified
    echo Usage: regression_check.bat ^<current.json^> ^<baseline.json^>
    exit /b 1
)

if "%BASELINE%"=="" (
    echo ERROR: No baseline specified
    echo Usage: regression_check.bat ^<current.json^> ^<baseline.json^>
    exit /b 1
)

if not exist "%CURRENT%" (
    echo ERROR: Current results not found: %CURRENT%
    exit /b 1
)

if not exist "%BASELINE%" (
    echo ERROR: Baseline not found: %BASELINE%
    exit /b 1
)

echo Current:  %CURRENT%
echo Baseline: %BASELINE%
echo.

python check_regression.py "%CURRENT%" "%BASELINE%"
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE%==0 (
    echo.
    echo ✓ No regressions detected
) else (
    echo.
    echo ✗ REGRESSIONS DETECTED - Review required
)

exit /b %EXIT_CODE%
