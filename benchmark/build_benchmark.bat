@echo off
cd /d d:\src\benchmark

echo Building Standardized Benchmark Harness...

g++ -std=c++17 -O3 -mavx2 -mfma -I. -I../../rawrxd/src -I../../rawrxd/src/inference -I../../rawrxd/src/model -I../../rawrxd/src/runtime -o run_standardized_benchmark.exe ^
    run_standardized_benchmark.cpp ^
    standardized_benchmark.cpp ^
    ../../rawrxd/src/inference/quantized_tensor.cpp ^
    ../../rawrxd/src/inference/transformer_layer.cpp ^
    ../../rawrxd/src/model/model_context.cpp ^
    ../../rawrxd/src/runtime/tokenizer_runtime.cpp ^
    2>&1

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo.
    echo Usage: run_standardized_benchmark.exe ^<model_path^> [options]
    echo.
    echo Example:
    echo   run_standardized_benchmark.exe d:\rawrxd\src\codestral22b.gguf --quick
) else (
    echo.
    echo Build failed!
)

pause
