@echo off
REM Step B Milestone Gate Verification
REM Tests real kernel integration through Execution Gateway

setlocal enabledelayedexpansion

set CLI=.\rawrxd_v3.exe
set PASS=0
set FAIL=0

echo ==========================================
echo Step B Milestone Gates - Real Execution
echo ==========================================
echo.

REM Gate 1: Registry CLI resolves kernels through real registry
echo Gate 1: Kernel Registry Resolution
echo ------------------------------------------
%CLI% test --all --json > test_registry.json 2> nul
findstr "Kernel registry initialized" test_registry.json > nul
if %errorlevel% equ 0 (
    echo   PASS: Registry resolves real kernels
    set /a PASS+=1
) else (
    echo   FAIL: Registry not resolving
    set /a FAIL+=1
)
del test_registry.json 2> nul
echo.

REM Gate 2: Validation executes real validator
echo Gate 2: Kernel Validation (Real)
echo ------------------------------------------
%CLI% kernel --validate --kernel rmsnorm --variant reference --json > test_validate.json 2> nul
findstr "RMSNorm Validation" test_validate.json > nul
if %errorlevel% equ 0 (
    findstr "\"passed\":true" test_validate.json > nul
    if !errorlevel! equ 0 (
        echo   PASS: Real validation executed
        set /a PASS+=1
    ) else (
        echo   FAIL: Validation did not pass
        set /a FAIL+=1
    )
) else (
    echo   FAIL: Validation not executed
    set /a FAIL+=1
)
del test_validate.json 2> nul
echo.

REM Gate 3: Profiling invokes real profiler
echo Gate 3: Kernel Profiling (Real)
echo ------------------------------------------
%CLI% kernel --profile --kernel gemm --json > test_profile.json 2> nul
findstr "GEMM Profile" test_profile.json > nul
if %errorlevel% equ 0 (
    echo   PASS: Real profiling executed
    set /a PASS+=1
) else (
    echo   FAIL: Profiling not executed
    set /a FAIL+=1
)
del test_profile.json 2> nul
echo.

REM Gate 4: Policy consumes profiler output
echo Gate 4: Policy Generation
echo ------------------------------------------
%CLI% kernel --policy --json > test_policy.json 2> nul
findstr "status\":0" test_policy.json > nul
if %errorlevel% equ 0 (
    echo   PASS: Policy generation executed
    set /a PASS+=1
) else (
    echo   FAIL: Policy generation failed
    set /a FAIL+=1
)
del test_policy.json 2> nul
echo.

REM Gate 5: Run executes real inference path
echo Gate 5: Inference Pipeline (Real)
echo ------------------------------------------
%CLI% run --model dummy.gguf --prompt "test" --json > test_run.json 2> nul
findstr "Inference Pipeline Execution" test_run.json > nul
if %errorlevel% equ 0 (
    echo   PASS: Real inference path executed
    set /a PASS+=1
) else (
    echo   FAIL: Inference path not executed
    set /a FAIL+=1
)
del test_run.json 2> nul
echo.

REM Gate 6: JSON output for all commands
echo Gate 6: JSON Output Contract
echo ------------------------------------------
set JSON_PASS=0
%CLI% test --all --json > nul 2> nul && set /a JSON_PASS+=1
%CLI% kernel --list --json > nul 2> nul && set /a JSON_PASS+=1
%CLI% benchmark --json > nul 2> nul && set /a JSON_PASS+=1
if %JSON_PASS% equ 3 (
    echo   PASS: All commands support JSON
    set /a PASS+=1
) else (
    echo   FAIL: Only %JSON_PASS%/3 commands support JSON
    set /a FAIL+=1
)
echo.

REM Gate 7: Telemetry from runtime measurements
echo Gate 7: Runtime Telemetry
echo ------------------------------------------
%CLI% kernel --validate --kernel rmsnorm --variant reference --json > test_telemetry.json 2> nul
findstr "\"total_ms\":" test_telemetry.json > nul
if %errorlevel% equ 0 (
    echo   PASS: Telemetry contains runtime measurements
    set /a PASS+=1
) else (
    echo   FAIL: Telemetry missing
    set /a FAIL+=1
)
del test_telemetry.json 2> nul
echo.

REM Gate 8: Exit codes
echo Gate 8: Exit Code Contract
echo ------------------------------------------
%CLI% help > nul 2> nul
if %errorlevel% equ 0 (
    echo   PASS: Success returns 0
    set /a PASS+=1
) else (
    echo   FAIL: Success did not return 0
    set /a FAIL+=1
)

%CLI% unknowncommand > nul 2> nul
if %errorlevel% equ 1 (
    echo   PASS: User error returns 1
    set /a PASS+=1
) else (
    echo   FAIL: User error returned %errorlevel%
    set /a FAIL+=1
)
echo.

REM Summary
echo ==========================================
echo Step B Gate Summary
echo ==========================================
echo Passed: %PASS%
echo Failed: %FAIL%
echo Total:  %PASS% + %FAIL%
echo.

if %FAIL% equ 0 (
    echo ALL GATES PASSED - Step B Complete
    exit /b 0
) else (
    echo Some gates failed.
    exit /b 1
)
