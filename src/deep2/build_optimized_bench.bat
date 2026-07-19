@echo off
REM Build script for optimized Deep2 E2E benchmark
REM Uses MSVC for maximum performance

setlocal enabledelayedexpansion

REM Find Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Please install Visual Studio.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo ERROR: Visual Studio environment not found.
    exit /b 1
)

echo Found Visual Studio at: %VS_PATH%

REM Initialize VS environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    echo ERROR: Failed to initialize VS environment
    exit /b 1
)

REM Set paths
set "SRC_DIR=%~dp0"
set "OBJ_DIR=%SRC_DIR%\obj"
set "BIN_DIR=%SRC_DIR%\bin"

REM Create directories
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

echo.
echo ========================================
echo Building Optimized Deep2 E2E Benchmark
echo ========================================
echo.

REM Compile MASM kernel
echo [1/4] Assembling Deep2 kernel (MASM x64)...
ml64.exe /c /nologo /Fo "%OBJ_DIR%\deep2_kernel.obj" "%SRC_DIR%\deep2_kernel.asm"
if errorlevel 1 (
    echo ERROR: MASM assembly failed
    exit /b 1
)
echo       OK: deep2_kernel.obj

REM Compile C++ benchmark
echo.
echo [2/4] Compiling optimized benchmark (C++17)...
cl.exe /c /nologo /EHsc /O2 /arch:AVX2 /DNDEBUG /Fo "%OBJ_DIR%\deep2_end_to_end_bench_optimized.obj" "%SRC_DIR%\deep2_end_to_end_bench_optimized.cpp"
if errorlevel 1 (
    echo ERROR: C++ compilation failed
    exit /b 1
)
echo       OK: deep2_end_to_end_bench_optimized.obj

REM Link
echo.
echo [3/4] Linking...
link.exe /nologo /OUT:"%BIN_DIR%\deep2_end_to_end_bench_optimized.exe" ^
    "%OBJ_DIR%\deep2_end_to_end_bench_optimized.obj" ^
    "%OBJ_DIR%\deep2_kernel.obj" ^
    kernel32.lib psapi.lib ^
    /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)
echo       OK: deep2_end_to_end_bench_optimized.exe

REM Run benchmark
echo.
echo [4/4] Running benchmark...
echo.
"%BIN_DIR%\deep2_end_to_end_bench_optimized.exe" tinyllama.gguf 256 4096 1

set EXIT_CODE=%ERRORLEVEL%

echo.
echo ========================================
if %EXIT_CODE% == 0 (
    echo Build and run: SUCCESS
) else (
    echo Build succeeded but run failed with code %EXIT_CODE%
)
echo ========================================

exit /b %EXIT_CODE%
