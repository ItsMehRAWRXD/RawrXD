@echo off
cd /d d:\rawrxd

echo Building RawrXD v4 with quantized tensor support...

g++ -std=c++17 -O2 -mavx2 -mfma -I. -I./src -I./src/inference -o rawrxd_v4.exe ^
    src\cli\unified_cli_v3_real.cpp ^
    src\execution\execution_gateway_impl.cpp ^
    src\execution\kernel_validator.cpp ^
    src\model\model_context.cpp ^
    src\runtime\tokenizer_runtime.cpp ^
    src\inference\transformer_layer.cpp ^
    src\inference\quantized_tensor.cpp ^
    kernels\kernel_registry.cpp ^
    kernels\fused_quant_gemm.cpp ^
    kernels\compression_codec.cpp ^
    2>&1

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful: rawrxd_v4.exe
    dir rawrxd_v4.exe
) else (
    echo.
    echo Build failed with error code %ERRORLEVEL%
)

pause
