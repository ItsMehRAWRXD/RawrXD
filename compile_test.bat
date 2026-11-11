@echo off
setlocal EnableDelayedExpansion

echo ========================================
echo Compiling Test Harness
echo ========================================

REM Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment
    exit /b 1
)

cd /d d:\rawrxd

echo.
echo Compiling test_quantized_kernels.cpp...
cl.exe /std:c++17 /O2 /EHsc /W4 /Iinclude /Iinclude\kernels /Febin\test_quantized_kernels.exe src\kernels\test_quantized_kernels.cpp lib\RawrXD_QuantizedKernels.lib /link /NODEFAULTLIB:libcmt.lib kernel32.lib

if errorlevel 1 (
    echo FAILED to compile
    exit /b 1
)

echo.
echo SUCCESS: test_quantized_kernels.exe built
echo.
echo To run: bin\test_quantized_kernels.exe
echo   gguf_test.exe "F:\OllamaModels\Qwen3.5-40B-Claude-4.6-Opus-Deckard-Heretic-Uncensored-Thinking.Q4_K_M.gguf"
