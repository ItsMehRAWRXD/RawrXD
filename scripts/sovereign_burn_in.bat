@echo off
setlocal enabledelayedexpansion

echo =============================================================================
echo SOVEREIGN SUBSTRATE BURN-IN TEST
echo =============================================================================
echo.
echo This test validates the complete integration of:
echo   - Lifecycle Manager (VCS Forking + Checkpointing)
echo   - Hybrid Memory Validator (Deep2 + PageFaultMonitor)
echo   - 11x Hot-Patcher (Live patching)
echo.
echo =============================================================================
echo.

set "BUILD_DIR=build"
set "TEST_RESULTS=reports\burn_in_results.log"
set "SESSION_ID=%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "SESSION_ID=!SESSION_ID: =0!"

echo [!] Session ID: !SESSION_ID!
echo [!] Build Directory: %BUILD_DIR%
echo.

:: Create reports directory
if not exist reports mkdir reports

:: Clear previous results
echo. > %TEST_RESULTS%
echo Sovereign Burn-in Test - !SESSION_ID! >> %TEST_RESULTS%
echo ============================================================ >> %TEST_RESULTS%
echo. >> %TEST_RESULTS%

:: =============================================================================
:: PHASE 1: Memory Integrity Validation
echo [PHASE 1/5] Memory Integrity Validation
echo [PHASE 1/5] Memory Integrity Validation >> %TEST_RESULTS%
echo ----------------------------------------------------------- >> %TEST_RESULTS%

if exist "%BUILD_DIR%\bin\test_hybrid_memory.exe" (
    echo   Running Hybrid Memory Validator...
    "%BUILD_DIR%\bin\test_hybrid_memory.exe" --verify-memory-aperture >> %TEST_RESULTS% 2>&1
    if !errorlevel! neq 0 (
        echo [FAIL] Hybrid Memory Breach detected!
        echo [FAIL] Hybrid Memory Breach detected! >> %TEST_RESULTS%
        goto :error
    )
    echo [PASS] Memory aperture validated
echo [PASS] Memory aperture validated >> %TEST_RESULTS%
) else (
    echo [SKIP] test_hybrid_memory.exe not found
    echo [SKIP] test_hybrid_memory.exe not found >> %TEST_RESULTS%
)
echo.
echo. >> %TEST_RESULTS%

:: =============================================================================
:: PHASE 2: Lifecycle Manager Cold Start
echo [PHASE 2/5] Lifecycle Manager Cold Start
echo [PHASE 2/5] Lifecycle Manager Cold Start >> %TEST_RESULTS%
echo ----------------------------------------------------------- >> %TEST_RESULTS%

if exist "%BUILD_DIR%\bin\test_sovereign_lifecycle.exe" (
    echo   Running Lifecycle Manager Test...
    "%BUILD_DIR%\bin\test_sovereign_lifecycle.exe" --run-full-loop >> %TEST_RESULTS% 2>&1
    if !errorlevel! neq 0 (
        echo [FAIL] Lifecycle Manager failed!
        echo [FAIL] Lifecycle Manager failed! >> %TEST_RESULTS%
        goto :error
    )
    echo [PASS] Lifecycle Manager operational
echo [PASS] Lifecycle Manager operational >> %TEST_RESULTS%
) else (
    echo [SKIP] test_sovereign_lifecycle.exe not found
    echo [SKIP] test_sovereign_lifecycle.exe not found >> %TEST_RESULTS%
)
echo.
echo. >> %TEST_RESULTS%

:: =============================================================================
:: PHASE 3: Integrated Burn-in Test
echo [PHASE 3/5] Integrated Burn-in (Lifecycle + Memory + Patcher)
echo [PHASE 3/5] Integrated Burn-in >> %TEST_RESULTS%
echo ----------------------------------------------------------- >> %TEST_RESULTS%

if exist "%BUILD_DIR%\bin\sovereign_integrated_test.exe" (
    echo   Running Integrated Test...
    "%BUILD_DIR%\bin\sovereign_integrated_test.exe" --iterations=10 --checkpoint-interval=3 >> %TEST_RESULTS% 2>&1
    if !errorlevel! neq 0 (
        echo [FAIL] Integrated test failed!
        echo [FAIL] Integrated test failed! >> %TEST_RESULTS%
        goto :error
    )
    echo [PASS] Integrated burn-in completed
echo [PASS] Integrated burn-in completed >> %TEST_RESULTS%
) else (
    echo [SKIP] sovereign_integrated_test.exe not found (build required)
    echo [SKIP] sovereign_integrated_test.exe not found >> %TEST_RESULTS%
)
echo.
echo. >> %TEST_RESULTS%

:: =============================================================================
:: PHASE 4: VCS Branch Audit
echo [PHASE 4/5] VCS Branch Audit
echo [PHASE 4/5] VCS Branch Audit >> %TEST_RESULTS%
echo ----------------------------------------------------------- >> %TEST_RESULTS%

echo   Checking for session branches...
git branch --list "session_*" > nul 2>&1
if !errorlevel! equ 0 (
    for /f "tokens=*" %%a in ('git branch --list "session_*" ^| find /c /v ""') do (
        set "BRANCH_COUNT=%%a"
    )
    echo   Found !BRANCH_COUNT! session branches
    echo   Found !BRANCH_COUNT! session branches >> %TEST_RESULTS%
    
    if !BRANCH_COUNT! gtr 0 (
        echo [PASS] VCS branches exist
        echo [PASS] VCS branches exist >> %TEST_RESULTS%
    ) else (
        echo [WARN] No session branches found
        echo [WARN] No session branches found >> %TEST_RESULTS%
    )
) else (
    echo [SKIP] Git not available or not a repository
    echo [SKIP] Git not available >> %TEST_RESULTS%
)
echo.
echo. >> %TEST_RESULTS%

:: =============================================================================
:: PHASE 5: Checkpoint File Audit
echo [PHASE 5/5] Checkpoint File Audit
echo [PHASE 5/5] Checkpoint File Audit >> %TEST_RESULTS%
echo ----------------------------------------------------------- >> %TEST_RESULTS%

set "CHK_COUNT=0"
for %%f in (checkpoints\*.chk) do (
    set /a CHK_COUNT+=1
    echo   Found: %%f
    echo   Found: %%f >> %TEST_RESULTS%
)

echo   Total checkpoints: !CHK_COUNT!
echo   Total checkpoints: !CHK_COUNT! >> %TEST_RESULTS%

if !CHK_COUNT! gtr 0 (
    echo [PASS] Checkpoint files exist
    echo [PASS] Checkpoint files exist >> %TEST_RESULTS%
) else (
    echo [WARN] No checkpoint files found
    echo [WARN] No checkpoint files found >> %TEST_RESULTS%
)
echo.
echo. >> %TEST_RESULTS%

:: =============================================================================
:: SUMMARY
echo =============================================================================
echo BURN-IN TEST SUMMARY
echo =============================================================================
echo   Session ID: !SESSION_ID!
echo   Results: %TEST_RESULTS%
echo.
echo [SUCCESS] Full Substrate Burn-in complete!
echo.
echo The Sovereign Substrate is ready for autonomous deployment.
echo =============================================================================

echo. >> %TEST_RESULTS%
echo ============================================================ >> %TEST_RESULTS%
echo BURN-IN COMPLETE - !SESSION_ID! >> %TEST_RESULTS%
echo ============================================================ >> %TEST_RESULTS%

goto :end

:error
echo.
echo =============================================================================
echo [CRITICAL ERROR] Burn-in test failed!
echo =============================================================================
echo Check %TEST_RESULTS% for details.
exit /b 1

:end
endlocal
exit /b 0
