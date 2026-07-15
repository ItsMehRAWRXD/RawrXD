@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD Validation Framework - Build Tests
echo ============================================
echo.

set "CC=gcc"
set "CFLAGS=-O2 -Wall -mavx2 -mfma"
set "PASSED=0"
set "FAILED=0"

echo Building CPU tests...
cd /d "%~dp0\cpu"

for %%f in (*.c) do (
    echo   Building %%~nf...
    "%CC%" %CFLAGS% -o "%%~nf.exe" "%%f" -lm
    if errorlevel 1 (
        echo     [FAIL] %%~nf
        set /a FAILED+=1
    ) else (
        echo     [OK] %%~nf.exe
        set /a PASSED+=1
    )
)

echo.
echo Building Kernel tests...
cd /d "%~dp0\kernels"

for %%f in (*.c) do (
    echo   Building %%~nf...
    "%CC%" %CFLAGS% -o "%%~nf.exe" "%%f" -lm
    if errorlevel 1 (
        echo     [FAIL] %%~nf
        set /a FAILED+=1
    ) else (
        echo     [OK] %%~nf.exe
        set /a PASSED+=1
    )
)

echo.
echo ============================================
echo Build Summary
echo ============================================
echo Passed: %PASSED%
echo Failed: %FAILED%
echo.

if %FAILED%==0 (
    echo [OK] All tests built successfully
    exit /b 0
) else (
    echo [FAIL] Some builds failed
    exit /b 1
)
