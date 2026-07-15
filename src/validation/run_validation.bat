@echo off
REM Quick validation runner for RawrXD

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Validation Runner
echo ==========================================
echo.

set VALIDATOR=..\..\build-validation\rawrxd_validate.exe

if not exist %VALIDATOR% (
    echo ERROR: Validator not found. Building...
    call build_validate.bat
    if errorlevel 1 (
        echo ERROR: Build failed
        exit /b 1
    )
)

set MODEL_PATH=
set OUTPUT_PATH=validation_report

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
if "%~1"=="-o" (
    set OUTPUT_PATH=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--output" (
    set OUTPUT_PATH=%~2
    shift
    shift
    goto parse_args
)
if "%~1"=="--quick" (
    set QUICK_MODE=1
    shift
    goto parse_args
)
shift
goto parse_args

:run
echo Running validation...
if defined MODEL_PATH (
    echo Model: %MODEL_PATH%
) else (
    echo Model: (none - kernel tests only)
)
echo Output: %OUTPUT_PATH%
echo.

%VALIDATOR% -m "%MODEL_PATH%" -o "%OUTPUT_PATH%" -v

set EXIT_CODE=%ERRORLEVEL%

echo.
if %EXIT_CODE%==0 (
    echo ==========================================
    echo ✓ VALIDATION PASSED
    echo ==========================================
) else (
    echo ==========================================
    echo ✗ VALIDATION FAILED
    echo ==========================================
)

if exist %OUTPUT_PATH%.json (
    echo JSON report: %OUTPUT_PATH%.json
)
if exist %OUTPUT_PATH%.html (
    echo HTML report: %OUTPUT_PATH%.html
)

exit /b %EXIT_CODE%
