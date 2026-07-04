@echo off
REM Build script for RawrXD-Script Benchmark Harness
REM Requires: Visual Studio 2022 (cl.exe)

echo ============================================
echo  RawrXD-Script Benchmark Build
echo ============================================
echo.

set VSDIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717
set PATH=%VSDIR%\bin\Hostx64\x64;%PATH%
set INCLUDE=%VSDIR%\include;%INCLUDE%
set LIB=%VSDIR%\lib\x64;%LIB%

echo [1/2] Compiling benchmark harness...
cl /O2 /EHsc /std:c++20 /W4 /Fe:benchmark.exe benchmark_harness.cpp ^
   ..\parser\parser.cpp ^
   ..\compiler\compiler.cpp ^
   ..\lexer\lexer.cpp ^
   /link kernel32.lib psapi.lib

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo [2/2] Build complete: benchmark.exe
echo.
echo Usage:
echo   benchmark.exe           Run all benchmarks
echo   benchmark.exe --quick   Run reduced iterations
echo   benchmark.exe --fuzz    Run security fuzz tests
echo   benchmark.exe --help    Show help
echo Usage:
echo   %OUTPUT%           - Run standard benchmarks
echo   %OUTPUT% --quick   - Run reduced iteration count
echo   %OUTPUT% --fuzz    - Run security fuzz tests
echo   %OUTPUT% --help    - Show help
echo.

pause
