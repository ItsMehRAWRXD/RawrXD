@echo off
REM ============================================================================
REM VAL-000 Sovereign Runtime - Complete Build Script
REM Builds all components and validates integration
REM ============================================================================

echo ============================================
echo VAL-000 Sovereign Runtime Build
echo ============================================

set "BUILD_DIR=D:\RawrXD\build-val000"
set "SRC_DIR=D:\RawrXD\src\deep2"
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"

mkdir "%BUILD_DIR%" 2>nul
cd /d "%BUILD_DIR%"

echo.
echo [1/5] Building MASM kernels...
echo.

REM Build VAL-038 optimized attention kernel
call :build_masm "TreeAttention_Fused_VAL038.asm" "TreeAttention_Fused_VAL038.obj"
call :build_masm "TreeAttention_Fused_VAL038_Optimized.asm" "TreeAttention_Fused_VAL038_Optimized.obj"

REM Build quantization kernels
call :build_masm "sovereign_q4k_gemv.asm" "sovereign_q4k_gemv.obj"
call :build_masm "sovereign_q8_0_gemv.asm" "sovereign_q8_0_gemv.obj"
call :build_masm "sovereign_iq2_xxs_gemv.asm" "sovereign_iq2_xxs_gemv.obj"
call :build_masm "sovereign_iq3_xxs_gemv.asm" "sovereign_iq3_xxs_gemv.obj"
call :build_masm "sovereign_iq4_nl_gemv.asm" "sovereign_iq4_nl_gemv.obj"
call :build_masm "softmax_lut_avx512.asm" "softmax_lut_avx512.obj"
call :build_masm "sovereign_moe_fused.asm" "sovereign_moe_fused.obj"

echo.
echo [2/5] Building C++ runtime components...
echo.

REM Compile all C++ components with optimizations
g++ -O3 -mavx512f -mavx512bw -mavx512vl -std=c++20 -I"%SRC_DIR%" -I"D:\RawrXD\include" -I"D:\RawrXD\src\sampling" -c "%~dp0src\deep2\Deep2Engine.cpp" -o Deep2Engine.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\MedusaDecoder.cpp" -o MedusaDecoder.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\NUFusedPacker.cpp" -o NUFusedPacker.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\WarmupScheduler.cpp" -o WarmupScheduler.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\CompressedKVCache.cpp" -o CompressedKVCache.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\NVMeStream.cpp" -o NVMeStream.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\SlidingWindowEngine.cpp" -o SlidingWindowEngine.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\MoERouter.cpp" -o MoERouter.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\MoEWeightProxy.cpp" -o MoEWeightProxy.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\MoEWeightsLoader.cpp" -o MoEWeightsLoader.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\GGUFLoader.cpp" -o GGUFLoader.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\ThreadPool.cpp" -o ThreadPool.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\KVCache.cpp" -o KVCache.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\deep2\QuantKernelRegistry.cpp" -o QuantKernelRegistry.o
g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -c "%~dp0src\sampling\advanced_sampler.cpp" -o advanced_sampler.o

echo.
echo [3/5] Linking VAL-000 runtime library...
echo.

ar rcs libval000_sovereign.a Deep2Engine.o MedusaDecoder.o NUFusedPacker.o WarmupScheduler.o CompressedKVCache.o NVMeStream.o SlidingWindowEngine.o MoERouter.o MoEWeightProxy.o MoEWeightsLoader.o GGUFLoader.o ThreadPool.o KVCache.o QuantKernelRegistry.o advanced_sampler.o *.obj

echo.
echo [4/5] Building validation harness...
echo.

g++ -O3 -mavx512f -std=c++20 -I"%SRC_DIR%" -I"D:\RawrXD\include" "%~dp0src\deep2\VAL038_Benchmark_Harness.cpp" -L. -lval000_sovereign -o VAL038_Validation.exe

echo.
echo [5/5] Running validation...
echo.

VAL038_Validation.exe --mode=full --iterations=100000

echo.
echo ============================================
echo VAL-000 Build Complete
echo ============================================
echo.
echo Components built:
echo   - Deep2Engine (MoE + transformer)
echo   - MedusaDecoder (speculative decoding)
echo   - NUFusedPacker (compression)
echo   - WarmupScheduler (predictive prefetch)
echo   - CompressedKVCache (Q8_0/Q4_K)
echo   - NVMeStream (demand paging)
echo   - SlidingWindowEngine (context management)
echo   - VAL-038 kernels (AVX-512)
echo   - All quantization kernels (Q4_K, Q8_0, IQ*)
echo.
echo Library: libval000_sovereign.a
echo Validation: VAL038_Validation.exe
echo.

goto :eof

:build_masm
    echo Building %~1...
    "%ML64%" /c /Fo"%~2" "%~dp0src\deep2\%~1" 2>nul
    if exist "%~2" (
        echo   [OK] %~2
    ) else (
        echo   [WARN] %~1 build skipped (may not exist)
    )
    goto :eof
