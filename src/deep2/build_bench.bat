@echo off
REM ============================================================================
REM build_bench.bat - Build Deep2 Bare-Metal Benchmark
REM Pure MASM x64, no CRT dependencies
REM ============================================================================

echo [+] Building Deep2 Bare-Metal Benchmark...
echo.

REM Check for ml64.exe
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"

if not exist "%ML64%" (
    echo [-] ERROR: ml64.exe not found at %ML64%
    exit /b 1
)

REM Create output directory
if not exist "obj" mkdir obj

echo [+] Assembling benchmark harness...
"%ML64%" /c /nologo /Fo obj\bench_deep2.obj bench_deep2.asm
if errorlevel 1 (
    echo [-] ERROR: Failed to assemble bench_deep2.asm
    exit /b 1
)
echo [+] bench_deep2.asm assembled successfully

echo.
echo [+] Assembling Deep2 kernels...
"%ML64%" /c /nologo /Fo obj\deep2_kernel.obj deep2_kernel.asm
if errorlevel 1 (
    echo [-] ERROR: Failed to assemble deep2_kernel.asm
    exit /b 1
)
echo [+] deep2_kernel.asm assembled successfully

echo.
echo [+] Linking bare-metal executable...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:bench_deep2.exe obj\bench_deep2.obj obj\deep2_kernel.obj kernel32.lib
if errorlevel 1 (
    echo [-] ERROR: Failed to link benchmark executable
    exit /b 1
)

echo.
echo [+] Build complete!
echo     Executable: bench_deep2.exe
echo.
echo [+] To run benchmark:
echo     .\Run-Deep2Bench.ps1
echo.
