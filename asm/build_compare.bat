@echo off
REM ============================================================================
REM build_compare.bat - Build Comparison Benchmark
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
echo Building Comparison Benchmark
echo ============================================
echo.

REM Compile
echo [1/2] Compiling benchmark_compare.cpp...
cl.exe /O2 /EHsc /arch:AVX2 /Fe:benchmark_compare.exe benchmark_compare.cpp Sovereign_Legacy_Kernels.lib Sovereign_Intrinsics.lib kernel32.lib /link /SUBSYSTEM:CONSOLE /NODEFAULTLIB:uuid.lib
if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)
echo [OK] benchmark_compare.exe
echo.

REM Run
echo ============================================
echo Running Comparison
echo ============================================
echo.
benchmark_compare.exe

echo.
echo ============================================
echo Complete
echo ============================================
