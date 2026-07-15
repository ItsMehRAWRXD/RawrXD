@echo off
REM ============================================================================
REM RawrXD Phase 7D: Determinism Test Script
REM Runs the same prompt 3 times and verifies identical outputs
REM ============================================================================

setlocal EnableDelayedExpansion

echo ============================================================================
echo Phase 7D: Determinism Test
echo ============================================================================
echo.

REM Configuration
set "MODEL=%~1"
set "PROMPT=%~2"
set "TOKENS=%~3"

if "%MODEL%"=="" set "MODEL=models\tinyllama.gguf"
if "%PROMPT%"=="" set "PROMPT=Hello world"
if "%TOKENS%"=="" set "TOKENS=10"

echo Configuration:
echo   Model: %MODEL%
echo   Prompt: "%PROMPT%"
echo   Tokens: %TOKENS%
echo.

REM Check model exists
if not exist "%MODEL%" (
    echo ERROR: Model not found: %MODEL%
    exit /b 1
)

REM Create output directory
set "OUTDIR=determinism_test_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "OUTDIR=!OUTDIR: =0!"
mkdir "%OUTDIR%"

echo Running 3 identical inference passes...
echo.

REM Run 3 times with same seed
for /l %%i in (1,1,3) do (
    echo [Run %%i/3] Generating...
    
    .\build_cli\RawrXD_RealModel.exe ^
        --model "%MODEL%" ^
        --prompt "%PROMPT%" ^
        --tokens %TOKENS% ^
        --seed 42 ^
        --temp 0.8 ^
        --top-p 0.9 ^
        --top-k 40 ^
        --enable-proofs ^
        --proof-out "%OUTDIR%\proof_run%%i.rawrproof" ^
        > "%OUTDIR%\output_run%%i.txt" 2> "%OUTDIR%\log_run%%i.txt"
    
    if !ERRORLEVEL! neq 0 (
        echo   ERROR: Run %%i failed
        type "%OUTDIR%\log_run%%i.txt"
        exit /b 1
    )
    
    echo   Completed, proof: %OUTDIR%\proof_run%%i.rawrproof
)

echo.
echo Computing hashes...
echo.

REM Compute SHA256 of each proof
for /l %%i in (1,1,3) do (
    certutil -hashfile "%OUTDIR%\proof_run%%i.rawrproof" SHA256 | findstr /v "hash" | findstr /v "CertUtil" > "%OUTDIR%\hash_run%%i.txt"
)

REM Compare hashes
set /p HASH1=<"%OUTDIR%\hash_run1.txt"
set /p HASH2=<"%OUTDIR%\hash_run2.txt"
set /p HASH3=<"%OUTDIR%\hash_run3.txt"

echo Hash Run 1: %HASH1%
echo Hash Run 2: %HASH2%
echo Hash Run 3: %HASH3%
echo.

REM Check if all match
if "%HASH1%"=="%HASH2%" (
    if "%HASH2%"=="%HASH3%" (
        echo RESULT: ✓ ALL HASHES MATCH - Determinism verified!
        echo.
        echo Output text from Run 1:
        type "%OUTDIR%\output_run1.txt"
        echo.
        echo Test artifacts saved to: %OUTDIR%\
        exit /b 0
    )
)

echo RESULT: ✗ HASH MISMATCH - Determinism failed!
echo.
echo Differences:
if not "%HASH1%"=="%HASH2%" echo   Run 1 != Run 2
if not "%HASH2%"=="%HASH3%" echo   Run 2 != Run 3
if not "%HASH1%"=="%HASH3%" echo   Run 1 != Run 3
echo.
echo Check logs in: %OUTDIR%\
exit /b 1
