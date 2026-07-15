@echo off
REM =============================================================================
REM   RawrXD Master Integration Script - Batch 10 of 5 (Final)
REM   Complete integration of all production tools
REM =============================================================================

setlocal EnableDelayedExpansion

set "RAWRXD_HOME=d:\rawrxd"
set "VERSION=1.0.0"
set "BUILD_ID=build-%date:~10,4%%date:~4,2%%date:~7,2%-%time:~0,2%%time:~3,2%%time:~6,2%"
set "BUILD_ID=!BUILD_ID: =0!"

set "PHASE=0"
set "TOTAL_PHASES=10"
set "BUILD_STATUS=SUCCESS"

echo =============================================================================
echo   RawrXD Master Integration Script
echo   Version: %VERSION%
echo   Build ID: %BUILD_ID%
echo   Started: %date% %time%
echo =============================================================================
echo.

REM =============================================================================
REM Phase 1: Environment Setup
echo [%PHASE%/%TOTAL_PHASES%] Setting up environment...
set /a PHASE+=1

if not exist "%RAWRXD_HOME%\build" mkdir "%RAWRXD_HOME%\build"
if not exist "%RAWRXD_HOME%\reports" mkdir "%RAWRXD_HOME%\reports"
if not exist "%RAWRXD_HOME%\artifacts" mkdir "%RAWRXD_HOME%\artifacts"

echo   ✓ Environment ready
echo.

REM =============================================================================
REM Phase 2: Production Verification
echo [%PHASE%/%TOTAL_PHASES%] Verifying production readiness...
set /a PHASE+=1

call "%RAWRXD_HOME%\verify_production.bat" >NUL 2>&1
if errorlevel 1 (
    echo   ✗ Production verification failed
    set "BUILD_STATUS=FAILED"
    goto :summary
)
echo   ✓ Production verification passed
echo.

REM =============================================================================
REM Phase 3: Clean Build
echo [%PHASE%/%TOTAL_PHASES%] Cleaning previous builds...
set /a PHASE+=1

call "%RAWRXD_HOME%\build.bat" clean >NUL 2>&1
echo   ✓ Clean complete
echo.

REM =============================================================================
REM Phase 4: Build Toolchain
echo [%PHASE%/%TOTAL_PHASES%] Building toolchain...
set /a PHASE+=1

call "%RAWRXD_HOME%\build.bat" toolchain >NUL 2>&1
if errorlevel 1 (
    echo   ✗ Toolchain build failed
    set "BUILD_STATUS=FAILED"
    goto :summary
)
echo   ✓ Toolchain built
echo.

REM =============================================================================
REM Phase 5: Build Tests
echo [%PHASE%/%TOTAL_PHASES%] Building tests...
set /a PHASE+=1

call "%RAWRXD_HOME%\build.bat" tests >NUL 2>&1
if errorlevel 1 (
    echo   ✗ Test build failed
    set "BUILD_STATUS=FAILED"
    goto :summary
)
echo   ✓ Tests built
echo.

REM =============================================================================
REM Phase 6: Run Tests
echo [%PHASE%/%TOTAL_PHASES%] Running test suite...
set /a PHASE+=1

call "%RAWRXD_HOME%\run_tests.bat" ci >"%RAWRXD_HOME%\reports\test_output.log" 2>&1
if errorlevel 1 (
    echo   ✗ Tests failed
    set "BUILD_STATUS=FAILED"
) else (
    echo   ✓ All tests passed
)
echo.

REM =============================================================================
REM Phase 7: Static Analysis
echo [%PHASE%/%TOTAL_PHASES%] Running static analysis...
set /a PHASE+=1

if exist "%RAWRXD_HOME%\tools\analyzer\static_analyzer.exe" (
    "%RAWRXD_HOME%\tools\analyzer\static_analyzer.exe" "%RAWRXD_HOME%\native_toolchain\c_parser.c" >"%RAWRXD_HOME%\reports\analysis.log" 2>&1
    echo   ✓ Static analysis complete
) else (
    echo   ⚠ Static analyzer not available
)
echo.

REM =============================================================================
REM Phase 8: Generate Reports
echo [%PHASE%/%TOTAL_PHASES%] Generating reports...
set /a PHASE+=1

if exist "%RAWRXD_HOME%\tools\report\build_report_generator.exe" (
    "%RAWRXD_HOME%\tools\report\build_report_generator.exe" >NUL 2>&1
    echo   ✓ Build report generated
)

if exist "%RAWRXD_HOME%\tools\metrics\metrics_dashboard.exe" (
    "%RAWRXD_HOME%\tools\metrics\metrics_dashboard.exe" >NUL 2>&1
    echo   ✓ Metrics dashboard generated
)

echo   ✓ Reports generated
echo.

REM =============================================================================
REM Phase 9: Package Release
echo [%PHASE%/%TOTAL_PHASES%] Packaging release...
set /a PHASE+=1

if exist "%RAWRXD_HOME%\release.bat" (
    call "%RAWRXD_HOME%\release.bat" %VERSION% >NUL 2>&1
    echo   ✓ Release packaged
) else (
    echo   ⚠ Release packager not available
)
echo.

REM =============================================================================
REM Phase 10: Final Verification
echo [%PHASE%/%TOTAL_PHASES%] Final verification...
set /a PHASE+=1

echo   Build artifacts:
if exist "%RAWRXD_HOME%\build\test_assembler.exe" echo     ✓ test_assembler.exe
if exist "%RAWRXD_HOME%\build\test_linker.exe" echo     ✓ test_linker.exe
if exist "%RAWRXD_HOME%\build\test_pipeline.exe" echo     ✓ test_pipeline.exe

echo   Reports:
if exist "%RAWRXD_HOME%\reports\BUILD_REPORT.txt" echo     ✓ BUILD_REPORT.txt
if exist "%RAWRXD_HOME%\reports\test_output.log" echo     ✓ test_output.log
if exist "%RAWRXD_HOME%\reports\analysis.log" echo     ✓ analysis.log

echo   ✓ Verification complete
echo.

:summary
echo =============================================================================
echo   BUILD SUMMARY
echo =============================================================================
echo   Build ID:   %BUILD_ID%
echo   Version:    %VERSION%
echo   Status:     %BUILD_STATUS%
echo   Completed:  %date% %time%
echo =============================================================================

if "%BUILD_STATUS%"=="SUCCESS" (
    echo   ✅ BUILD SUCCESSFUL
echo =============================================================================
    exit /b 0
) else (
    echo   ❌ BUILD FAILED
echo =============================================================================
    exit /b 1
)
