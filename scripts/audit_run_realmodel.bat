@echo off
REM ============================================================================
REM RawrXD Phase 7D: Real Model Audit Pipeline
REM Automated verification pipeline for GGUF model inference
REM ============================================================================
REM Usage: audit_run_realmodel.bat <model.gguf> [mode]
REM   mode: quick (default), full, stress
REM ============================================================================

setlocal EnableDelayedExpansion

REM Parse arguments
set "MODEL_PATH=%~1"
set "MODE=%~2"
if "%MODE%"=="" set "MODE=quick"

REM Validate inputs
if "%MODEL_PATH%"=="" (
    echo ERROR: Model path required
    echo Usage: %0 ^<model.gguf^> [quick^|full^|stress]
    exit /b 1
)

if not exist "%MODEL_PATH%" (
    echo ERROR: Model not found: %MODEL_PATH%
    exit /b 1
)

REM Configuration
set "RAWRXD_ROOT=%~dp0.."
set "BUILD_DIR=%RAWRXD_ROOT%\build_cli"
set "AUDIT_DIR=%RAWRXD_ROOT%\audit_output"
set "TIMESTAMP=%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TIMESTAMP=!TIMESTAMP: =0!"
set "RUN_DIR=%AUDIT_DIR%\run_!TIMESTAMP!"

REM Create directories
if not exist "%AUDIT_DIR%" mkdir "%AUDIT_DIR%"
mkdir "%RUN_DIR%"

REM ============================================================================
REM Header
REM ============================================================================
echo ============================================================================
echo RawrXD Phase 7D: Real Model Audit Pipeline
echo ============================================================================
echo.
echo Model: %MODEL_PATH%
echo Mode: %MODE%
echo Output: %RUN_DIR%
echo Timestamp: %TIMESTAMP%
echo.

REM ============================================================================
REM Step 1: Model Validation
echo [1/7] Validating model file...
REM ============================================================================
set "MODEL_HASH_FILE=%RUN_DIR%\model.sha256"
certutil -hashfile "%MODEL_PATH%" SHA256 | findstr /v "hash" | findstr /v "CertUtil" > "%MODEL_HASH_FILE%"
set /p MODEL_HASH=<"%MODEL_HASH_FILE%"
echo   SHA256: %MODEL_HASH%
echo   Saved to: %MODEL_HASH_FILE%
echo.

REM ============================================================================
REM Step 2: Metadata Extraction
echo [2/7] Extracting model metadata...
REM ============================================================================
set "META_FILE=%RUN_DIR%\metadata.txt"
if exist "%BUILD_DIR%\gguf_info.exe" (
    "%BUILD_DIR%\gguf_info.exe" "%MODEL_PATH%" > "%META_FILE%" 2>nul
    echo   Metadata extracted to: %META_FILE%
) else (
    echo   WARNING: gguf_info.exe not found, skipping metadata extraction
)
echo.

REM ============================================================================
REM Step 3: Test Configuration
echo [3/7] Configuring test scenarios...
REM ============================================================================
set "TEST_PROMPT=The capital of France is"
set "TEST_SEED=42"

if "%MODE%"=="quick" (
    set "TEST_TOKENS=10"
    set "SCENARIOS=baseline"
) else if "%MODE%"=="full" (
    set "TEST_TOKENS=50"
    set "SCENARIOS=baseline temperature top_p top_k combined"
) else if "%MODE%"=="stress" (
    set "TEST_TOKENS=100"
    set "SCENARIOS=baseline temperature top_p top_k combined long_context"
) else (
    echo ERROR: Unknown mode: %MODE%
    exit /b 1
)

echo   Prompt: "%TEST_PROMPT%"
echo   Seed: %TEST_SEED%
echo   Tokens: %TEST_TOKENS%
echo   Scenarios: %SCENARIOS%
echo.

REM ============================================================================
REM Step 4: Build Verification
echo [4/7] Verifying build artifacts...
REM ============================================================================
set "BINARIES_OK=1"
if not exist "%BUILD_DIR%\RawrXD_RealModel.exe" (
    echo   ERROR: RawrXD_RealModel.exe not found
    set "BINARIES_OK=0"
)
if not exist "%BUILD_DIR%\verify_proof.exe" (
    echo   ERROR: verify_proof.exe not found
    set "BINARIES_OK=0"
)

if "%BINARIES_OK%"=="0" (
    echo.
    echo Build artifacts missing. Run build first:
    echo   cd %BUILD_DIR%
    echo   build_realmodel.bat
    exit /b 1
)
echo   All binaries present
echo.

REM ============================================================================
REM Step 5: Run Inference with Checkpoints
echo [5/7] Running inference with checkpoint capture...
REM ============================================================================
set "INFERENCE_LOG=%RUN_DIR%\inference.log"
set "PROOF_FILE=%RUN_DIR%\inference.rawrproof"
set "OUTPUT_FILE=%RUN_DIR%\output.txt"

echo   Running: RawrXD_RealModel.exe
echo   Command: --model "%MODEL_PATH%" --prompt "%TEST_PROMPT%" --tokens %TEST_TOKENS% --seed %TEST_SEED% --enable-proofs --proof-out "%PROOF_FILE%"
echo.

"%BUILD_DIR%\RawrXD_RealModel.exe" ^
    --model "%MODEL_PATH%" ^
    --prompt "%TEST_PROMPT%" ^
    --tokens %TEST_TOKENS% ^
    --seed %TEST_SEED% ^
    --temp 0.8 ^
    --top-p 0.9 ^
    --top-k 40 ^
    --enable-proofs ^
    --proof-out "%PROOF_FILE%" ^
    --cpu-only ^
    > "%OUTPUT_FILE%" 2> "%INFERENCE_LOG%"

set "INFERENCE_EXIT=%ERRORLEVEL%"

if %INFERENCE_EXIT% neq 0 (
    echo   ERROR: Inference failed with exit code %INFERENCE_EXIT%
    echo   See: %INFERENCE_LOG%
    type "%INFERENCE_LOG%"
    exit /b 1
)

echo   Inference completed successfully
echo   Output: %OUTPUT_FILE%
echo   Proof: %PROOF_FILE%
echo.

REM Show generated text
echo   Generated text:
echo   ----------------------------------------
type "%OUTPUT_FILE%"
echo   ----------------------------------------
echo.

REM ============================================================================
REM Step 6: Verify Proof Chain
echo [6/7] Verifying proof chain...
REM ============================================================================
set "VERIFY_LOG=%RUN_DIR%\verification.log"

if exist "%PROOF_FILE%" (
    "%BUILD_DIR%\verify_proof.exe" "%MODEL_PATH%" "%PROOF_FILE%" > "%VERIFY_LOG%" 2>&1
    set "VERIFY_EXIT=%ERRORLEVEL%"
    
    if %VERIFY_EXIT% equ 0 (
        echo   ✓ Proof verification PASSED
echo   Verification log: %VERIFY_LOG%
    ) else (
        echo   ✗ Proof verification FAILED
echo   See: %VERIFY_LOG%
        type "%VERIFY_LOG%"
    )
) else (
    echo   WARNING: Proof file not generated
    set "VERIFY_EXIT=1"
)
echo.

REM ============================================================================
REM Step 7: Generate Audit Report
echo [7/7] Generating audit report...
REM ============================================================================
set "REPORT_FILE=%RUN_DIR%\audit_report.json"
set "MANIFEST_FILE=%RUN_DIR%\MANIFEST.txt"

(
echo {
echo   "audit_version": "7D.1",
echo   "timestamp": "%TIMESTAMP%",
echo   "mode": "%MODE%",
echo   "model": {
echo     "path": "%MODEL_PATH:=\%",
echo     "sha256": "%MODEL_HASH%"
echo   },
echo   "test_configuration": {
echo     "prompt": "%TEST_PROMPT%",
echo     "seed": %TEST_SEED%,
echo     "tokens": %TEST_TOKENS%
echo   },
echo   "results": {
echo     "inference_exit_code": %INFERENCE_EXIT%,
echo     "verification_exit_code": %VERIFY_EXIT%,
echo     "proof_file": "inference.rawrproof",
echo     "output_file": "output.txt"
echo   },
echo   "artifacts": [
echo     "model.sha256",
echo     "metadata.txt",
echo     "inference.log",
echo     "inference.rawrproof",
echo     "output.txt",
echo     "verification.log",
echo     "audit_report.json",
echo     "MANIFEST.txt"
echo   ]
echo }
) > "%REPORT_FILE%"

REM Create human-readable manifest
(
echo RawrXD Phase 7D Audit Manifest
echo ================================
echo.
echo Run ID: %TIMESTAMP%
echo Mode: %MODE%
echo.
echo Model Information:
echo   Path: %MODEL_PATH%
echo   SHA256: %MODEL_HASH%
echo.
echo Test Configuration:
echo   Prompt: "%TEST_PROMPT%"
echo   Seed: %TEST_SEED%
echo   Tokens: %TEST_TOKENS%
echo.
echo Results:
echo   Inference: %INFERENCE_EXIT%
echo   Verification: %VERIFY_EXIT%
echo.
echo Artifacts:
echo   - model.sha256: Model file hash
echo   - metadata.txt: GGUF metadata
echo   - inference.log: Inference execution log
echo   - inference.rawrproof: Cryptographic proof chain
echo   - output.txt: Generated text output
echo   - verification.log: Proof verification results
echo   - audit_report.json: Machine-readable report
echo   - MANIFEST.txt: This file
echo.
echo Status: %INFERENCE_EXIT%/%VERIFY_EXIT%
) > "%MANIFEST_FILE%"

echo   Report: %REPORT_FILE%
echo   Manifest: %MANIFEST_FILE%
echo.

REM ============================================================================
REM Summary
echo ============================================================================
echo Audit Complete
echo ============================================================================
echo.
echo Run directory: %RUN_DIR%
echo.
if %INFERENCE_EXIT% equ 0 (
    if %VERIFY_EXIT% equ 0 (
        echo Status: ✓ ALL CHECKS PASSED
echo.
echo The model executed successfully with full cryptographic verification.
    ) else (
        echo Status: ⚠ INFERENCE OK, VERIFICATION FAILED
echo.
echo Review verification.log for details.
    )
) else (
    echo Status: ✗ INFERENCE FAILED
echo.
echo Review inference.log for error details.
)
echo.
echo To view results:
echo   type "%RUN_DIR%\output.txt"
echo   type "%RUN_DIR%\verification.log"
echo.

endlocal
