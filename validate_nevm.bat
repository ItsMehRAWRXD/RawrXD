@echo off
REM ============================================================================
REM validate_nevm.bat
REM Quick validation script for N-EVM build
REM ============================================================================

echo ============================================================================
echo RawrXD N-EVM v0.2 Validation
echo ============================================================================
echo.

set "BUILD_DIR=D:\RawrXD\build\nevm"
set "BIN_DIR=%BUILD_DIR%\bin"

REM Check for required files
echo Checking build artifacts...
echo.

set "MISSING=0"

if not exist "%BIN_DIR%\RawrXD_NEVM.dll" (
    echo [MISSING] RawrXD_NEVM.dll
    set "MISSING=1"
) else (
    echo [FOUND]   RawrXD_NEVM.dll
)

if not exist "%BIN_DIR%\RawrXD_NEVM.lib" (
    echo [MISSING] RawrXD_NEVM.lib
    set "MISSING=1"
) else (
    echo [FOUND]   RawrXD_NEVM.lib
)

if not exist "%BIN_DIR%\test_nevm.exe" (
    echo [MISSING] test_nevm.exe
    set "MISSING=1"
) else (
    echo [FOUND]   test_nevm.exe
)

if not exist "%BIN_DIR%\nevm_test_harness.exe" (
    echo [MISSING] nevm_test_harness.exe
    set "MISSING=1"
) else (
    echo [FOUND]   nevm_test_harness.exe
)

echo.

if "%MISSING%"=="1" (
    echo ERROR: Build incomplete. Run build_nevm.bat first.
    exit /b 1
)

REM Run smoke test
echo Running smoke test...
echo.
"%BIN_DIR%\test_nevm.exe"
if errorlevel 1 (
    echo.
    echo ERROR: Smoke test failed
    exit /b 1
)

echo.
echo ============================================================================
echo Validation Complete
echo ============================================================================
echo.
echo N-EVM v0.2 is ready for use.
echo.
echo Next steps:
echo   1. Run comprehensive tests: %BIN_DIR%\nevm_test_harness.exe
echo   2. Run benchmark: nevm_benchmark.exe ^<model.gguf^>
echo   3. Integrate with application
echo.
