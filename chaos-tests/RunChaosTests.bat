@echo off
REM RawrXD Chaos Engineering Quick Start
REM Usage: RunChaosTests.bat [scenario] [duration] [intensity]

cd /d "%~dp0"

set SCENARIO=%1
if "%SCENARIO%"=="" set SCENARIO=all

set DURATION=%2
if "%DURATION%"=="" set DURATION=60

set INTENSITY=%3
if "%INTENSITY%"=="" set INTENSITY=50

echo RawrXD Chaos Engineering Test Suite
echo ===================================
echo Scenario: %SCENARIO%
echo Duration: %DURATION% seconds
echo Intensity: %INTENSITY%%%
echo.

powershell -ExecutionPolicy Bypass -Command "& { .\chaos-test-suite.ps1 -Scenario '%SCENARIO%' -DurationSeconds %DURATION% -Intensity %INTENSITY% -Report }"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Tests FAILED with errors
    exit /b 1
)

echo.
echo Tests completed successfully
pause
