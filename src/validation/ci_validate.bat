@echo off
REM CI/CD validation script for RawrXD
REM Designed for automated testing in CI pipelines

setlocal enabledelayedexpansion

set VALIDATOR=..\..\build-validation\rawrxd_validate.exe
set MODEL=%1
set REPORT=validation_ci_%BUILD_BUILDID%

if "%MODEL%"=="" (
    echo ERROR: No model path provided
    echo Usage: ci_validate.bat ^<model_path^>
    exit /b 1
)

if not exist %VALIDATOR% (
    echo ERROR: Validator not found at %VALIDATOR%
    exit /b 1
)

if not exist "%MODEL%" (
    echo ERROR: Model not found at %MODEL%
    exit /b 1
)

echo Running CI validation...
echo Model: %MODEL%
echo.

%VALIDATOR% -m "%MODEL%" -o "%REPORT%" -v
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE%==0 (
    echo ##vso[task.setvariable variable=ValidationPassed]true
    echo Validation PASSED
) else (
    echo ##vso[task.setvariable variable=ValidationPassed]false
    echo Validation FAILED
)

exit /b %EXIT_CODE%
