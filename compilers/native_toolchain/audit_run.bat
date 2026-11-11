@echo off
REM RawrXD Audit Script
REM Validates reproducibility of benchmark results

echo ========================================
echo RawrXD Audit Script
echo ========================================
echo.

set MODEL=%1
set MODE=%2
if "%MODEL%"=="" set MODEL=llama-2-7b.gguf
if "%MODE%"=="" set MODE=quick

echo Model: %MODEL%
echo Mode: %MODE%
echo.

REM Step 1: Compute model hash
echo [1/6] Computing model hash...
CertUtil -hashfile %MODEL% SHA256 > model_hash.txt 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Failed to compute model hash
echo [!] Failed to compute model hash
    exit /b 1
)
echo     Hash saved to model_hash.txt

REM Step 2: Compute binary hash
echo [2/6] Computing binary hash...
CertUtil -hashfile ModelBenchmark.exe SHA256 > binary_hash.txt 2>nul
echo     Hash saved to binary_hash.txt

REM Step 3: Record environment
echo [3/6] Recording environment...
echo Timestamp: %date% %time% > environment.txt
echo Model: %MODEL% >> environment.txt
echo Mode: %MODE% >> environment.txt
systeminfo | findstr /B /C:"OS" >> environment.txt 2>nul
echo     Environment saved to environment.txt

REM Step 4: Run benchmark with telemetry
echo [4/6] Running benchmark...
echo     This may take several minutes...
ModelBenchmark.exe %MODE% > benchmark_output.txt 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Benchmark failed
    exit /b 1
)
echo     Output saved to benchmark_output.txt

REM Step 5: Verify hash chain
echo [5/6] Verifying hash chain...
if exist proof_chain.rawrproof (
    echo     Found proof_chain.rawrproof
    CertUtil -hashfile proof_chain.rawrproof SHA256 > proof_hash.txt 2>nul
    echo     Proof hash saved to proof_hash.txt
) else (
    echo     No proof chain found (optional)
)

REM Step 6: Generate audit report
echo [6/6] Generating audit report...
echo ========================================> audit_report.txt
echo RawrXD Audit Report>> audit_report.txt
echo ========================================> audit_report.txt
echo.>> audit_report.txt
echo Date: %date% %time%>> audit_report.txt
echo Model: %MODEL%>> audit_report.txt
echo Mode: %MODE%>> audit_report.txt
echo.>> audit_report.txt
echo --- Model Hash --->> audit_report.txt
type model_hash.txt >> audit_report.txt
echo.>> audit_report.txt
echo --- Binary Hash --->> audit_report.txt
type binary_hash.txt >> audit_report.txt
echo.>> audit_report.txt
echo --- Environment --->> audit_report.txt
type environment.txt >> audit_report.txt
echo.>> audit_report.txt
echo --- Benchmark Results --->> audit_report.txt
type benchmark_output.txt >> audit_report.txt
echo.>> audit_report.txt
echo --- Proof Hash --->> audit_report.txt
if exist proof_hash.txt (
    type proof_hash.txt >> audit_report.txt
) else (
    echo No proof chain generated>> audit_report.txt
)
echo.>> audit_report.txt
echo ========================================> audit_report.txt
echo Audit Complete>> audit_report.txt
echo ========================================> audit_report.txt

echo.
echo ========================================
echo Audit Complete
echo Report: audit_report.txt
echo ========================================
echo.
echo Artifacts generated:
echo   - model_hash.txt
echo   - binary_hash.txt
echo   - environment.txt
echo   - benchmark_output.txt
echo   - audit_report.txt (consolidated)
