@echo off
REM ============================================================================
REM run_validation_suite.bat
REM RawrXD N-EVM - Incremental Validation Pipeline
REM Runs validation in order: kernels → transformer → short inference → benchmark
REM ============================================================================

setlocal EnableDelayedExpansion

set "BUILD_DIR=D:\RawrXD\build\nevm\bin"
set "RESULTS_DIR=D:\RawrXD\benchmark_results"
set "MODEL_PATH=%~1"

if "%MODEL_PATH%"=="" (
    echo Usage: run_validation_suite.bat ^<model.gguf^>
    exit /b 1
)

if not exist "%MODEL_PATH%" (
    echo ERROR: Model not found: %MODEL_PATH%
    exit /b 1
)

REM Create results directory
if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

set "TIMESTAMP=%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TIMESTAMP=!TIMESTAMP: =0!"

echo ============================================================================
echo RawrXD N-EVM Validation Suite
echo ============================================================================
echo.
echo Model: %MODEL_PATH%
echo Timestamp: !TIMESTAMP!
echo Results: %RESULTS_DIR%
echo.

set "STAGE=0"
set "FAILED=0"

REM ============================================================================
REM Stage 1: Kernel Validation
REM ============================================================================
set /a STAGE+=1
echo [%STAGE%/4] Kernel Validation
echo ----------------------------------------

if not exist "%BUILD_DIR%\nevm_kernel_validation.exe" (
    echo [SKIP] Kernel validation executable not found
) else (
    "%BUILD_DIR%\nevm_kernel_validation.exe" > "%RESULTS_DIR%\kernel_validation_!TIMESTAMP!.log" 2>&1
    if errorlevel 1 (
        echo [FAIL] Kernel validation failed
        type "%RESULTS_DIR%\kernel_validation_!TIMESTAMP!.log"
        set "FAILED=1"
        goto :summary
    ) else (
        echo [PASS] All kernel tests passed
        type "%RESULTS_DIR%\kernel_validation_!TIMESTAMP!.log" | findstr "GOP/s"
    )
)
echo.

REM ============================================================================
REM Stage 2: Transformer Block Validation
REM ============================================================================
set /a STAGE+=1
echo [%STAGE%/4] Transformer Block Validation
echo ----------------------------------------

if not exist "%BUILD_DIR%\nevm_transformer_validation.exe" (
    echo [SKIP] Transformer validation executable not found
) else (
    "%BUILD_DIR%\nevm_transformer_validation.exe" > "%RESULTS_DIR%\transformer_validation_!TIMESTAMP!.log" 2>&1
    if errorlevel 1 (
        echo [FAIL] Transformer validation failed
        type "%RESULTS_DIR%\transformer_validation_!TIMESTAMP!.log"
        set "FAILED=1"
        goto :summary
    ) else (
        echo [PASS] Transformer block validation passed
        type "%RESULTS_DIR%\transformer_validation_!TIMESTAMP!.log" | findstr "seq_len"
    )
)
echo.

REM ============================================================================
REM Stage 3: Short Inference (32-128 tokens)
REM ============================================================================
set /a STAGE+=1
echo [%STAGE%/4] Short Inference Test (32 tokens)
echo ----------------------------------------

if not exist "%BUILD_DIR%\nevm_benchmark_runner.exe" (
    echo [SKIP] Benchmark runner not found
) else (
    "%BUILD_DIR%\nevm_benchmark_runner.exe" "%MODEL_PATH%" -n 32 -w 5 -o "%RESULTS_DIR%\short_inference_!TIMESTAMP!.json" > "%RESULTS_DIR%\short_inference_!TIMESTAMP!.log" 2>&1
    if errorlevel 1 (
        echo [FAIL] Short inference test failed
        type "%RESULTS_DIR%\short_inference_!TIMESTAMP!.log"
        set "FAILED=1"
        goto :summary
    ) else (
        echo [PASS] Short inference test passed
        type "%RESULTS_DIR%\short_inference_!TIMESTAMP!.log" | findstr "tok/s"
    )
)
echo.

REM ============================================================================
REM Stage 4: Long Decode Benchmark (1000+ tokens)
REM ============================================================================
set /a STAGE+=1
echo [%STAGE%/4] Long Decode Benchmark (1024 tokens)
echo ----------------------------------------

if not exist "%BUILD_DIR%\nevm_benchmark_runner.exe" (
    echo [SKIP] Benchmark runner not found
) else (
    "%BUILD_DIR%\nevm_benchmark_runner.exe" "%MODEL_PATH%" -n 1024 -w 10 -o "%RESULTS_DIR%\long_decode_!TIMESTAMP!.json" > "%RESULTS_DIR%\long_decode_!TIMESTAMP!.log" 2>&1
    if errorlevel 1 (
        echo [FAIL] Long decode benchmark failed
        type "%RESULTS_DIR%\long_decode_!TIMESTAMP!.log"
        set "FAILED=1"
        goto :summary
    ) else (
        echo [PASS] Long decode benchmark completed
        type "%RESULTS_DIR%\long_decode_!TIMESTAMP!.log" | findstr "tok/s"
    )
)
echo.

REM ============================================================================
REM Summary
REM ============================================================================
:summary
echo ============================================================================
echo Validation Summary
echo ============================================================================

if "%FAILED%"=="1" (
    echo STATUS: FAILED at stage %STAGE%
    echo.
    echo Results saved to: %RESULTS_DIR%
    echo.
    echo Failed logs:
    dir /b "%RESULTS_DIR%\*_!TIMESTAMP!.log" 2>nul
    exit /b 1
) else (
    echo STATUS: ALL STAGES PASSED
    echo.
    echo Results saved to: %RESULTS_DIR%
    echo.
    echo Generated files:
    dir /b "%RESULTS_DIR%\*_!TIMESTAMP%.*" 2>nul
    echo.
    echo Next steps:
    echo   1. Review results in %RESULTS_DIR%
    echo   2. Compare with llama.cpp baseline
    echo   3. Run cold-cache comparison: run_validation_suite.bat "%MODEL_PATH%" --cold
)

echo ============================================================================

endlocal
