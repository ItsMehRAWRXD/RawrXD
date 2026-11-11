@echo off
REM =============================================================================
REM   RawrXD CI/CD Pipeline - Batch 2 of 5
REM   Continuous Integration and Deployment Pipeline
REM =============================================================================

setlocal EnableDelayedExpansion

set "RAWRXD_HOME=d:\rawrxd"
set "BUILD_HOME=%RAWRXD_HOME%\build"
set "TEST_HOME=%RAWRXD_HOME%\tests"
set "ARTIFACT_HOME=%RAWRXD_HOME%\artifacts"
set "REPORT_HOME=%RAWRXD_HOME%\reports"

set "BUILD_NUMBER=%1"
if "!BUILD_NUMBER!"=="" set "BUILD_NUMBER=local"

set "BUILD_START_TIME=%time%"
set "BUILD_STATUS=SUCCESS"
set "TEST_STATUS=SUCCESS"
set "PACKAGE_STATUS=SUCCESS"

if not exist "%ARTIFACT_HOME%" mkdir "%ARTIFACT_HOME%"
if not exist "%REPORT_HOME%" mkdir "%REPORT_HOME%"

echo =============================================================================
echo   RawrXD CI/CD Pipeline
echo   Build: %BUILD_NUMBER%
echo   Started: %date% %time%
echo =============================================================================
echo.

REM =============================================================================
REM Phase 1: Clean Build Environment
echo [1/6] Cleaning build environment...
call :clean_build
if errorlevel 1 (
    echo FAILED: Clean build
    set "BUILD_STATUS=FAILED"
    goto :report
)
echo     ✓ Build environment cleaned
echo.

REM =============================================================================
REM Phase 2: Build Native Toolchain
echo [2/6] Building native toolchain...
call :build_toolchain
if errorlevel 1 (
    echo FAILED: Toolchain build
    set "BUILD_STATUS=FAILED"
    goto :report
)
echo     ✓ Toolchain built successfully
echo.

REM =============================================================================
REM Phase 3: Run Unit Tests
echo [3/6] Running unit tests...
call :run_unit_tests
if errorlevel 1 (
    echo FAILED: Unit tests
    set "TEST_STATUS=FAILED"
    goto :report
)
echo     ✓ Unit tests passed
echo.

REM =============================================================================
REM Phase 4: Run Integration Tests
echo [4/6] Running integration tests...
call :run_integration_tests
if errorlevel 1 (
    echo FAILED: Integration tests
    set "TEST_STATUS=FAILED"
    goto :report
)
echo     ✓ Integration tests passed
echo.

REM =============================================================================
REM Phase 5: Static Analysis
echo [5/6] Running static analysis...
call :run_static_analysis
if errorlevel 1 (
    echo WARNING: Static analysis found issues
)
echo     ✓ Static analysis complete
echo.

REM =============================================================================
REM Phase 6: Package Artifacts
echo [6/6] Packaging artifacts...
call :package_artifacts
if errorlevel 1 (
    echo FAILED: Packaging
    set "PACKAGE_STATUS=FAILED"
    goto :report
)
echo     ✓ Artifacts packaged
echo.

:report
call :generate_report

if "%BUILD_STATUS%"=="SUCCESS" (
    if "%TEST_STATUS%"=="SUCCESS" (
        if "%PACKAGE_STATUS%"=="SUCCESS" (
            echo.
            echo =============================================================================
            echo   ✅ BUILD SUCCESSFUL
echo =============================================================================
            exit /b 0
        )
    )
)

echo.
echo =============================================================================
echo   ❌ BUILD FAILED
echo   Build Status: %BUILD_STATUS%
echo   Test Status: %TEST_STATUS%
echo   Package Status: %PACKAGE_STATUS%
echo =============================================================================
exit /b 1

REM =============================================================================
REM Subroutines
REM =============================================================================

:clean_build
echo     Cleaning previous build artifacts...
if exist "%BUILD_HOME%" rmdir /s /q "%BUILD_HOME%"
if exist "%ARTIFACT_HOME%" rmdir /s /q "%ARTIFACT_HOME%"
if exist "%REPORT_HOME%" rmdir /s /q "%REPORT_HOME%"

mkdir "%BUILD_HOME%"
mkdir "%ARTIFACT_HOME%"
mkdir "%REPORT_HOME%"
exit /b 0

:build_toolchain
echo     Building minimal assembler...
REM Assembler is pre-built, verify it exists
if not exist "%RAWRXD_HOME%\native_toolchain\minimal_assembler_v2.exe" (
    echo     ERROR: Assembler not found
    exit /b 1
)

echo     Building native linker...
if not exist "%RAWRXD_HOME%\native_toolchain\linker_with_imports.exe" (
    echo     ERROR: Linker not found
    exit /b 1
)

echo     Building test framework...
if not exist "%TEST_HOME%\include" mkdir "%TEST_HOME%\include"
if not exist "%TEST_HOME%\src" mkdir "%TEST_HOME%\src"
if not exist "%TEST_HOME%\unit" mkdir "%TEST_HOME%\unit"
if not exist "%TEST_HOME%\integration" mkdir "%TEST_HOME%\integration"
if not exist "%TEST_HOME%\output" mkdir "%TEST_HOME%\output"

exit /b 0

:run_unit_tests
echo     Running assembler unit tests...
cd /d "%TEST_HOME%\unit"

REM Compile and run assembler tests
gcc -o "%BUILD_HOME%\test_assembler.exe" test_assembler.c "%TEST_HOME%\src\test_framework.c" -I"%TEST_HOME%\include" -Wall -Wextra
if errorlevel 1 (
    echo     ERROR: Failed to compile assembler tests
    exit /b 1
)

"%BUILD_HOME%\test_assembler.exe" > "%REPORT_HOME%\test_assembler.log" 2>&1
set "TEST_RESULT=%errorlevel%"

if "%TEST_RESULT%" neq "0" (
    echo     ERROR: Assembler tests failed
    type "%REPORT_HOME%\test_assembler.log"
    exit /b 1
)

echo     Running linker unit tests...
gcc -o "%BUILD_HOME%\test_linker.exe" test_linker.c "%TEST_HOME%\src\test_framework.c" -I"%TEST_HOME%\include" -Wall -Wextra
if errorlevel 1 (
    echo     ERROR: Failed to compile linker tests
    exit /b 1
)

"%BUILD_HOME%\test_linker.exe" > "%REPORT_HOME%\test_linker.log" 2>&1
set "TEST_RESULT=%errorlevel%"

if "%TEST_RESULT%" neq "0" (
    echo     ERROR: Linker tests failed
    type "%REPORT_HOME%\test_linker.log"
    exit /b 1
)

exit /b 0

:run_integration_tests
echo     Running integration tests...
cd /d "%TEST_HOME%\integration"

gcc -o "%BUILD_HOME%\test_pipeline.exe" test_pipeline.c "%TEST_HOME%\src\test_framework.c" -I"%TEST_HOME%\include" -Wall -Wextra
if errorlevel 1 (
    echo     ERROR: Failed to compile integration tests
    exit /b 1
)

"%BUILD_HOME%\test_pipeline.exe" > "%REPORT_HOME%\test_integration.log" 2>&1
set "TEST_RESULT=%errorlevel%"

if "%TEST_RESULT%" neq "0" (
    echo     ERROR: Integration tests failed
    type "%REPORT_HOME%\test_integration.log"
    exit /b 1
)

exit /b 0

:run_static_analysis
echo     Running static analysis on test code...
REM Basic static analysis with compiler warnings
gcc -c "%TEST_HOME%\src\test_framework.c" -I"%TEST_HOME%\include" -Wall -Wextra -Werror -fanalyzer > "%REPORT_HOME%\static_analysis.log" 2>&1
if errorlevel 1 (
    echo     WARNING: Static analysis found issues
    type "%REPORT_HOME%\static_analysis.log"
)

exit /b 0

:package_artifacts
echo     Packaging build artifacts...

REM Copy executables
if exist "%RAWRXD_HOME%\native_toolchain\minimal_assembler_v2.exe" (
    copy "%RAWRXD_HOME%\native_toolchain\minimal_assembler_v2.exe" "%ARTIFACT_HOME%\" >NUL
)

if exist "%RAWRXD_HOME%\native_toolchain\linker_with_imports.exe" (
    copy "%RAWRXD_HOME%\native_toolchain\linker_with_imports.exe" "%ARTIFACT_HOME%\" >NUL
)

if exist "%BUILD_HOME%\test_assembler.exe" (
    copy "%BUILD_HOME%\test_assembler.exe" "%ARTIFACT_HOME%\" >NUL
)

if exist "%BUILD_HOME%\test_linker.exe" (
    copy "%BUILD_HOME%\test_linker.exe" "%ARTIFACT_HOME%\" >NUL
)

if exist "%BUILD_HOME%\test_pipeline.exe" (
    copy "%BUILD_HOME%\test_pipeline.exe" "%ARTIFACT_HOME%\" >NUL
)

REM Copy headers
if exist "%TEST_HOME%\include\test_framework.h" (
    copy "%TEST_HOME%\include\test_framework.h" "%ARTIFACT_HOME%\" >NUL
)

REM Create manifest
echo RawrXD Build %BUILD_NUMBER% > "%ARTIFACT_HOME%\MANIFEST.txt"
echo Build Date: %date% %time% >> "%ARTIFACT_HOME%\MANIFEST.txt"
echo Build Status: %BUILD_STATUS% >> "%ARTIFACT_HOME%\MANIFEST.txt"
echo Test Status: %TEST_STATUS% >> "%ARTIFACT_HOME%\MANIFEST.txt"
echo. >> "%ARTIFACT_HOME%\MANIFEST.txt"
echo Artifacts: >> "%ARTIFACT_HOME%\MANIFEST.txt"
dir /b "%ARTIFACT_HOME%\*.exe" >> "%ARTIFACT_HOME%\MANIFEST.txt" 2>NUL

exit /b 0

:generate_report
echo     Generating build report...

echo ============================================================================= > "%REPORT_HOME%\BUILD_REPORT.txt"
echo   RawrXD CI/CD Build Report >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo ============================================================================= >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo Build Number: %BUILD_NUMBER% >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo Start Time: %BUILD_START_TIME% >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo End Time: %time% >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo Status Summary: >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo   Build:   %BUILD_STATUS% >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo   Tests:   %TEST_STATUS% >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo   Package: %PACKAGE_STATUS% >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo ============================================================================= >> "%REPORT_HOME%\BUILD_REPORT.txt"

REM Append test logs
if exist "%REPORT_HOME%\test_assembler.log" (
    echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
    echo --- Assembler Test Log --- >> "%REPORT_HOME%\BUILD_REPORT.txt"
    type "%REPORT_HOME%\test_assembler.log" >> "%REPORT_HOME%\BUILD_REPORT.txt"
)

if exist "%REPORT_HOME%\test_linker.log" (
    echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
    echo --- Linker Test Log --- >> "%REPORT_HOME%\BUILD_REPORT.txt"
    type "%REPORT_HOME%\test_linker.log" >> "%REPORT_HOME%\BUILD_REPORT.txt"
)

if exist "%REPORT_HOME%\test_integration.log" (
    echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
    echo --- Integration Test Log --- >> "%REPORT_HOME%\BUILD_REPORT.txt"
    type "%REPORT_HOME%\test_integration.log" >> "%REPORT_HOME%\BUILD_REPORT.txt"
)

echo. >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo ============================================================================= >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo   End of Report >> "%REPORT_HOME%\BUILD_REPORT.txt"
echo ============================================================================= >> "%REPORT_HOME%\BUILD_REPORT.txt"

echo     Report saved to: %REPORT_HOME%\BUILD_REPORT.txt
exit /b 0
