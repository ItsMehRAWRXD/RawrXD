@echo off
REM Build standalone validation harness

echo ==========================================
echo RawrXD Standalone Validation Build
echo ==========================================
echo.

set OUTDIR=..\..\build-validation
if not exist %OUTDIR% mkdir %OUTDIR%

echo Building standalone_validate.c...
cl.exe /O2 /W3 /Fe%OUTDIR%\standalone_validate.exe standalone_validate.c

if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ==========================================
echo Build successful: %OUTDIR%\standalone_validate.exe
echo ==========================================
echo.
echo Run with: .\build-validation\standalone_validate.exe
echo.