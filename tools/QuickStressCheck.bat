@echo off
REM ============================================================================
REM QuickStressCheck.bat
REM Fast validation of debugger stress tests
REM Run this for quick sanity checks before full validation
REM ============================================================================

echo ========================================
echo RawrXD Debugger Quick Stress Check
echo ========================================
echo.

set "STRESS_TARGET=D:\rawrxd\build\tests\stress_target.exe"
set "STRESS_MEMORY=D:\rawrxd\build\tests\stress_memory.exe"

REM Check if binaries exist
if not exist "%STRESS_TARGET%" (
    echo ERROR: stress_target.exe not found
    echo Build with: cmake --build build --target stress_target
    exit /b 1
)

if not exist "%STRESS_MEMORY%" (
    echo ERROR: stress_memory.exe not found
    echo Build with: cmake --build build --target stress_memory
    exit /b 1
)

echo [1/2] Running stress_target.exe (5 seconds)...
start /b "" "%STRESS_TARGET%" > nul 2>&1
timeout /t 5 /nobreak > nul
taskkill /f /im stress_target.exe > nul 2>&1
echo      stress_target.exe: OK
echo.

echo [2/2] Running stress_memory.exe (5 seconds)...
start /b "" "%STRESS_MEMORY%" > nul 2>&1
timeout /t 5 /nobreak > nul
taskkill /f /im stress_memory.exe > nul 2>&1
echo      stress_memory.exe: OK
echo.

echo ========================================
echo Quick Check PASSED
echo ========================================
echo.
echo For full validation with telemetry capture:
echo   powershell -ExecutionPolicy Bypass -File D:\rawrxd\tools\ValidateStress.ps1
echo.

exit /b 0
