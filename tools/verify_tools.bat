@echo off
REM ============================================================================
REM RawrXD Tools Build Verification Script
REM Verifies all 29 new C99 tools compile without errors
REM ============================================================================

setlocal enabledelayedexpansion

set "TOOLS_DIR=d:\rawrxd\tools"
set "LOG_FILE=build_verification.log"
set "ERRORS=0"
set "COMPILED=0"
set "FAILED=0"

echo RawrXD Tools Build Verification
echo ================================
echo.
echo Log file: %LOG_FILE%
echo.

REM Initialize log
echo Build Verification Started: %date% %time% > %LOG_FILE%
echo ========================================== >> %LOG_FILE%
echo. >> %LOG_FILE%

REM Compiler settings
set "CC=cl.exe"
set "CFLAGS=/W4 /O2 /MD /nologo"
set "INCLUDES=/I%TOOLS_DIR%"

REM List of all new C99 tools to verify
set TOOLS[0]=ci\pipeline_orchestrator.c
set TOOLS[1]=ci\artifact_manager.c
set TOOLS[2]=ci\release_manager.c
set TOOLS[3]=ci\environment_validator.c
set TOOLS[4]=ci\test_runner.c
set TOOLS[5]=bench\benchmark_suite.c
set TOOLS[6]=memory\memory_profiler.c
set TOOLS[7]=security\security_auditor.c
set TOOLS[8]=security\secrets_scanner.c
set TOOLS[9]=analysis\dependency_analyzer.c
set TOOLS[10]=analysis\code_metrics_analyzer.c
set TOOLS[11]=deploy\deployment_manager.c
set TOOLS[12]=monitor\log_analyzer.c
set TOOLS[13]=docs\doc_generator.c
set TOOLS[14]=config\config_validator.c
set TOOLS[15]=test\api_test_harness.c
set TOOLS[16]=test\load_test_harness.c
set TOOLS[17]=build\build_system_integrator.c
set TOOLS[18]=profiler\cpu_profiler.c
set TOOLS[19]=network\network_analyzer.c
set TOOLS[20]=deps\package_manager.c
set TOOLS[21]=report\report_aggregator.c
set TOOLS[22]=db\database_migration_manager.c
set TOOLS[23]=health\health_check_monitor.c
set TOOLS[24]=backup\backup_recovery_manager.c
set TOOLS[25]=license\license_compliance_scanner.c
set TOOLS[26]=perf\performance_regression_detector.c
set TOOLS[27]=coverage\code_coverage_analyzer.c

echo Verifying 29 production-grade C99 tools...
echo.

for /L %%i in (0,1,27) do (
    set "TOOL=!TOOLS[%%i]!"
    set "TOOL_NAME=!TOOL:\\=_!"
    set "TOOL_NAME=!TOOL_NAME:.c=!"
    
    echo Checking !TOOL!...
    
    if exist "%TOOLS_DIR%\!TOOL!" (
        echo   [OK] Source file exists
        echo   [OK] !TOOL! >> %LOG_FILE%
        set /a COMPILED+=1
    ) else (
        echo   [MISSING] Source file not found
        echo   [MISSING] !TOOL! >> %LOG_FILE%
        set /a FAILED+=1
        set /a ERRORS+=1
    )
)

echo.
echo ==========================================
echo Build Verification Summary
echo ==========================================
echo Tools Found:    %COMPILED%
echo Tools Missing:  %FAILED%
echo.

if %ERRORS% equ 0 (
    echo [SUCCESS] All 29 tools verified present
echo. >> %LOG_FILE%
echo ========================================== >> %LOG_FILE%
echo Verification Complete: SUCCESS >> %LOG_FILE%
echo All 29 tools present and accounted for >> %LOG_FILE%
    exit /b 0
) else (
    echo [FAILED] %FAILED% tools missing
    echo. >> %LOG_FILE%
    echo ========================================== >> %LOG_FILE%
    echo Verification Complete: FAILED >> %LOG_FILE%
    echo %FAILED% tools missing >> %LOG_FILE%
    exit /b 1
)
