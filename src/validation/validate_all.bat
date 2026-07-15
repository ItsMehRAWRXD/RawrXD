@echo off
REM Comprehensive validation runner for RawrXD
REM Runs all validation suites and generates reports

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Comprehensive Validation Suite
echo ==========================================
echo.

set VALIDATOR=..\..\build-validation\rawrxd_validate.exe
set TIMESTAMP=%date:~10,4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set REPORT_DIR=..\..\validation-reports
set REPORT_NAME=validation_%TIMESTAMP%

if not exist %REPORT_DIR% mkdir %REPORT_DIR%

if not exist %VALIDATOR% (
    echo Validator not found. Building...
    call build_validate.bat
    if errorlevel 1 (
        echo ERROR: Build failed
        exit /b 1
    )
)

set MODEL_PATH=
set FULL_MODE=0

:parse_args
if "%~1"=="" goto run
if "%~1"=="-m" (
    set MODEL_PATH=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--model" (
    set MODEL_PATH=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--full" (
    set FULL_MODE=1
    shift
    goto parse_args
)
if "%~1"=="-h" (
    echo Usage: validate_all.bat [options]
    echo.
    echo Options:
    echo   -m, --model ^<path^>    Test model path for full validation
    echo   --full                  Run full validation (requires model)
    echo   -h                      Show this help
    exit /b 0
)
shift
goto parse_args

:run
echo Report: %REPORT_DIR%\%REPORT_NAME%
echo.

if defined MODEL_PATH (
    echo Running FULL validation with model: %MODEL_PATH%
    %VALIDATOR% -m "%MODEL_PATH%" -o "%REPORT_DIR%\%REPORT_NAME%" -v
) else (
    echo Running KERNEL-ONLY validation (no model provided)
    echo.
    echo To run full validation, use:
    echo   validate_all.bat -m path\to\model.gguf
    echo.
    %VALIDATOR% -o "%REPORT_DIR%\%REPORT_NAME%" -v
)

set EXIT_CODE=%ERRORLEVEL%

echo.
echo ==========================================
if %EXIT_CODE%==0 (
    echo ✓ VALIDATION PASSED
) else (
    echo ✗ VALIDATION FAILED
)
echo ==========================================
echo.
echo Reports generated:
echo   JSON: %REPORT_NAME%.json
echo   HTML: %REPORT_NAME%.html

exit /b %EXIT_CODE%
