@echo off
REM Run Milestone 1 integration test

setlocal EnableDelayedExpansion

set "BUILD_DIR=..\build\milestone1"
set "TEST_EXE=%BUILD_DIR%\milestone1_test.exe"

echo ============================================
echo RawrXD-Script Milestone 1 Test Runner
echo ============================================
echo.

if not exist "%TEST_EXE%" (
    echo Test executable not found. Building...
    call "%~dp0build_milestone1.bat"
    if !ERRORLEVEL! neq 0 (
        echo Build failed. Cannot run tests.
        exit /b 1
    )
)

echo Running tests...
echo.
"%TEST_EXE%"
set TEST_RESULT=!ERRORLEVEL!

echo.
if !TEST_RESULT! equ 0 (
    echo ============================================
    echo MILESTONE 1 PASSED
    echo ============================================
) else (
    echo ============================================
    echo MILESTONE 1 FAILED
    echo ============================================
    echo Check output above for details
)

exit /b !TEST_RESULT!
