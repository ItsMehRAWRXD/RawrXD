@echo off
REM ============================================================================
REM build_e2e_bench.bat - Build Deep2 End-to-End Benchmark
REM ============================================================================

echo [+] Building Deep2 End-to-End Benchmark...
echo.

REM Compile C++ benchmark
g++ -O2 -mavx2 -o deep2_end_to_end_bench.exe deep2_end_to_end_bench.cpp Deep2.cpp obj\deep2_kernel.obj -lpsapi -static

if errorlevel 1 (
    echo [-] ERROR: Failed to build benchmark
    exit /b 1
)

echo [+] Build complete!
echo     Executable: deep2_end_to_end_bench.exe
echo.
echo [+] To run benchmark:
echo     .\deep2_end_to_end_bench.exe [model.gguf] [num_tokens] [warmup_tokens]
echo.
