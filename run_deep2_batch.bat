@echo off
:: Run script for Deep2 Batch Model Stress-Test Harness
:: Executes Discovery-Load-Benchmark-Validation for all models in models/ directory

echo ==========================================
echo Deep2 Batch Model Stress-Test Runner
echo ==========================================
echo.

:: Check if executable exists
if not exist build_fix3\bin\Deep2_Batch_Test.exe (
    echo [ERROR] Executable not found: build_fix3\bin\Deep2_Batch_Test.exe
    echo Run build_deep2_batch.bat first
    exit /b 1
)

:: Check if models directory exists
if not exist models\ (
    echo [WARNING] models/ directory not found
    echo Creating models/ directory...
    mkdir models
    echo [INFO] Place .bin, .gguf, or .ggml model files in models/ directory
    echo.
)

:: Set model path (default: models/)
set MODEL_PATH=models
if not "%~1"=="" set MODEL_PATH=%~1

:: Set manifest path (optional, default: none)
set MANIFEST_PATH=
if not "%~2"=="" set MANIFEST_PATH=%~2

echo [CONFIG] Model path: %MODEL_PATH%
if not "%MANIFEST_PATH%"=="" echo [CONFIG] Manifest path: %MANIFEST_PATH%
echo.

:: Run the batch test
echo [EXEC] Running Deep2 batch test...
echo.
if "%MANIFEST_PATH%"=="" (
    build_fix3\bin\Deep2_Batch_Test.exe %MODEL_PATH%
) else (
    build_fix3\bin\Deep2_Batch_Test.exe %MODEL_PATH% %MANIFEST_PATH%
)
set EXITCODE=%ERRORLEVEL%

echo.
echo ==========================================
if %EXITCODE% equ 0 (
    echo [PASS] Deep2 batch test completed
) else (
    echo [COMPLETE] Deep2 batch test finished with warnings (exit code: %EXITCODE%)
)
echo Check output above for detailed results
echo ==========================================

exit /b %EXITCODE%
