@echo off
REM ============================================================================
REM RawrXD Phase 7D: Determinism Verification Script
REM Runs multiple inferences and verifies hashes are identical
REM ============================================================================

setlocal EnableDelayedExpansion

REM Parse arguments
set "MODEL_PATH=%~1"
set "RUNS=%~2"
if "%RUNS%"=="" set "RUNS=3"

if "%MODEL_PATH%"=="" (
    echo Usage: %0 ^<model.gguf^> [number_of_runs]
    exit /b 1
)

if not exist "%MODEL_PATH%" (
    echo ERROR: Model not found: %MODEL_PATH%
    exit /b 1
)

set "RAWRXD_ROOT=%~dp0.."
set "RAWRXD_EXE=%RAWRXD_ROOT%\build_cli\RawrXD_RealModel.exe"

if not exist "%RAWRXD_EXE%" (
    echo ERROR: RawrXD_RealModel.exe not found at %RAWRXD_EXE%
    exit /b 1
)

echo ============================================================================
echo RawrXD Phase 7D: Determinism Verification
echo ============================================================================
echo.
echo Model: %MODEL_PATH%
echo Runs: %RUNS%
echo.

REM Create temp directory for proofs
set "TEMP_DIR=%TEMP%\rawrxd_det_%RANDOM%"
mkdir "%TEMP_DIR%"

set "FIRST_HASH="
set "ALL_MATCH=1"

for /L %%i in (1,1,%RUNS%) do (
    echo [Run %%i/%RUNS%] Running inference...
    
    set "PROOF_FILE=%TEMP_DIR%\run_%%i.rawrproof"
    
    REM Run inference and capture output
    "%RAWRXD_EXE%" "%MODEL_PATH%" --enable-proofs --proof-out "!PROOF_FILE!" >"%TEMP_DIR%\run_%%i.log" 2>&1
    
    if !ERRORLEVEL! neq 0 (
        echo   ERROR: Inference failed
        set "ALL_MATCH=0"
        goto :cleanup
    )
    
    REM Extract header hash from output
    for /f "tokens=3" %%h in ('findstr "Header hash:" "%TEMP_DIR%\run_%%i.log"') do (
        set "CURRENT_HASH=%%h"
    )
    
    echo   Header hash: !CURRENT_HASH!
    
    REM Check against first hash
    if "%%i"=="1" (
        set "FIRST_HASH=!CURRENT_HASH!"
        echo   [Baseline established]
    ) else (
        if "!CURRENT_HASH!" neq "!FIRST_HASH!" (
            echo   ERROR: Hash mismatch! Expected !FIRST_HASH!, got !CURRENT_HASH!
            set "ALL_MATCH=0"
        ) else (
            echo   [Match confirmed]
        )
    )
    
    echo.
)

echo ============================================================================
if "%ALL_MATCH%"=="1" (
    echo RESULT: DETERMINISM VERIFIED ✅
    echo All %RUNS% runs produced identical hashes.
    echo Baseline hash: %FIRST_HASH%
) else (
    echo RESULT: DETERMINISM FAILED ❌
    echo Hashes differ between runs!
)
echo ============================================================================

:cleanup
REM Cleanup temp files
rmdir /s /q "%TEMP_DIR%" 2>nul

if "%ALL_MATCH%"=="1" (
    exit /b 0
) else (
    exit /b 1
)
