@echo off
REM ============================================================================
REM build_benchmark.bat - Build Phase 7B Benchmark
REM ============================================================================

cd /d d:\src\asm

REM Find VS2022
for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

if not defined VSPATH (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS2022 found at: %VSPATH%

REM Setup environment
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"

echo ============================================
echo Building Phase 7B Benchmark
echo ============================================
echo.

REM Compile benchmark
echo [1/2] Compiling benchmark_kernels.cpp...
cl.exe /O2 /EHsc /arch:AVX2 /Fe:benchmark_kernels.exe benchmark_kernels.cpp Sovereign_Legacy_Kernels.lib kernel32.lib /link /SUBSYSTEM:CONSOLE /NODEFAULTLIB:uuid.lib
if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)
echo [OK] benchmark_kernels.exe
echo.

REM Run benchmark
echo ============================================
echo Running Benchmark
echo ============================================
echo.
benchmark_kernels.exe

echo.
echo ============================================
echo Benchmark Complete
echo ============================================
