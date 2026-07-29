@echo off
REM ============================================================================
REM build_val038.bat - Build VAL-038 Fused Attention Benchmark Harness
REM
REM Assembles MASM kernels and compiles the C++ harness with the same flags
REM as the final runtime path.
REM
REM Usage: build_val038.bat
REM ============================================================================

setlocal

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set SRC=d:\RawrXD\src\deep2

echo [*] Assembling VAL-038 Fused Attention Kernel...
%ML64% /c /coff /Fo TreeAttention_Fused_VAL038.obj %SRC%\TreeAttention_Fused_VAL038.asm
if errorlevel 1 (
    echo [!] Assembly failed: TreeAttention_Fused_VAL038.asm
    exit /b 1
)

echo [*] Assembling AVX-512 LUT Softmax Kernel...
%ML64% /c /coff /Fo softmax_lut_avx512.obj %SRC%\softmax_lut_avx512.asm
if errorlevel 1 (
    echo [!] Assembly failed: softmax_lut_avx512.asm
    exit /b 1
)

echo [*] Compiling C++ Validation Harness...
%CL% /O2 /arch:AVX512 /std:c++17 /EHsc /I%SRC% ^
    %SRC%\VAL038_Benchmark_Harness.cpp ^
    /Fe:VAL038_Benchmark_Harness.exe ^
    /link TreeAttention_Fused_VAL038.obj softmax_lut_avx512.obj
if errorlevel 1 (
    echo [!] Compilation failed: VAL038_Benchmark_Harness.cpp
    exit /b 1
)

echo [*] Build sequence complete. Ready for target execution.
echo [*] Run: VAL038_Benchmark_Harness.exe

endlocal