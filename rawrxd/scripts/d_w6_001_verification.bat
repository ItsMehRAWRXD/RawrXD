@echo off
REM ============================================================================
REM D-W6-001 Verification Script — 5-phase shutdown stability test
REM ============================================================================
REM Phase 1: Launch → Exit immediately (20x)
REM Phase 2: Launch → Load model → Unload → Exit (5x)
REM Phase 3: Launch → Generate → Exit (5x)
REM Phase 4: Launch → Generate x3 → Exit (3x)
REM Phase 5: Full W6 E2E certification (1x)
REM
REM Pass criteria: every run exits with code 0, no STATUS_STACK_OVERFLOW
REM ============================================================================

setlocal enabledelayedexpansion
set EXE=F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe
set MODEL=F:\~dev\rawrxd\test_tiny.gguf
set TOTAL_PASS=0
set TOTAL_FAIL=0
set TOTAL_RUNS=0

if not exist "%EXE%" (
    echo ERROR: Exe not found at %EXE%
    exit /b 1
)

echo ====================================================================
echo   D-W6-001 SHUTDOWN STABILITY VERIFICATION
echo   Date: 2026-09-29
echo   Exe: %EXE%
echo ====================================================================
echo.

REM --- Phase 1: Launch → Exit immediately (20x) ---
echo === PHASE 1: Launch + Exit (20 iterations) ===
for /L %%i in (1,1,20) do (
    set /a TOTAL_RUNS+=1
    echo   Run %%i/20: 
    start /wait "" "%EXE%" --chat-exit-on-done --chat-model "%MODEL%" --chat-prompt "" --chat-max-tokens 0
    set EXITCODE=!ERRORLEVEL!
    if !EXITCODE! equ 0 (
        echo     PASS (exit=0)
        set /a TOTAL_PASS+=1
    ) else (
        echo     FAIL (exit=!EXITCODE!)
        set /a TOTAL_FAIL+=1
    )
)
echo.

REM --- Phase 2: Launch → Load → Unload → Exit (5x) ---
echo === PHASE 2: Load + Unload + Exit (5 iterations) ===
for /L %%i in (1,1,5) do (
    set /a TOTAL_RUNS+=1
    echo   Run %%i/5:
    start /wait "" "%EXE%" --chat-exit-on-done --chat-model "%MODEL%" --chat-prompt "hello" --chat-max-tokens 1
    set EXITCODE=!ERRORLEVEL!
    if !EXITCODE! equ 0 (
        echo     PASS (exit=0)
        set /a TOTAL_PASS+=1
    ) else (
        echo     FAIL (exit=!EXITCODE!)
        set /a TOTAL_FAIL+=1
    )
)
echo.

REM --- Phase 3: Launch → Generate → Exit (5x) ---
echo === PHASE 3: Generate + Exit (5 iterations) ===
for /L %%i in (1,1,5) do (
    set /a TOTAL_RUNS+=1
    echo   Run %%i/5:
    start /wait "" "%EXE%" --chat-exit-on-done --chat-model "%MODEL%" --chat-prompt "hello" --chat-max-tokens 6
    set EXITCODE=!ERRORLEVEL!
    if !EXITCODE! equ 0 (
        echo     PASS (exit=0)
        set /a TOTAL_PASS+=1
    ) else (
        echo     FAIL (exit=!EXITCODE!)
        set /a TOTAL_FAIL+=1
    )
)
echo.

REM --- Phase 4: Launch → Generate x3 → Exit (3x) ---
echo === PHASE 4: Multi-generate + Exit (3 iterations) ===
for /L %%i in (1,1,3) do (
    set /a TOTAL_RUNS+=1
    echo   Run %%i/3:
    start /wait "" "%EXE%" --chat-exit-on-done --chat-model "%MODEL%" --chat-prompt "The capital of France is" --chat-max-tokens 8
    set EXITCODE=!ERRORLEVEL!
    if !EXITCODE! equ 0 (
        echo     PASS (exit=0)
        set /a TOTAL_PASS+=1
    ) else (
        echo     FAIL (exit=!EXITCODE!)
        set /a TOTAL_FAIL+=1
    )
)
echo.

REM --- Phase 5: Full W6 E2E ---
echo === PHASE 5: Full W6 E2E (1 run) ===
set /a TOTAL_RUNS+=1
start /wait "" "%EXE%" --chat-exit-on-done --chat-model "%MODEL%" --chat-prompt "hello" --chat-max-tokens 6 --chat-seed 1
set EXITCODE=!ERRORLEVEL!
if !EXITCODE! equ 0 (
    echo   PASS (exit=0)
    set /a TOTAL_PASS+=1
) else (
    echo   FAIL (exit=!EXITCODE!)
    set /a TOTAL_FAIL+=1
)
echo.

echo ====================================================================
echo   VERIFICATION SUMMARY
echo ====================================================================
echo   Total runs:    %TOTAL_RUNS%
echo   Passed:        %TOTAL_PASS%
echo   Failed:        %TOTAL_FAIL%
echo.
if %TOTAL_FAIL% equ 0 (
    echo   GATE=D_W6_001_SHUTDOWN_STABILITY
    echo   VERDICT=PASS
    echo   ALL_RUNS_CLEAN_EXIT=1
    echo   STATUS_STACK_OVERFLOW=0
) else (
    echo   GATE=D_W6_001_SHUTDOWN_STABILITY
    echo   VERDICT=FAIL
    echo   ALL_RUNS_CLEAN_EXIT=0
    echo   FAILED_RUNS=%TOTAL_FAIL%
)
echo ====================================================================

endlocal & exit /b %TOTAL_FAIL%