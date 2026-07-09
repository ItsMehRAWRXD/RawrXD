@echo off
REM Build script for RawrXD Unified CLI
REM This compiles the unified CLI that exposes L4.x kernel capabilities

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Unified CLI Build
echo ==========================================
echo.

REM Set paths
set SRC_DIR=%~dp0src\cli
set BUILD_DIR=%~dp0build_unified_cli
set ML64_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Build directory: %BUILD_DIR%
echo.

REM Check for compiler
if not exist "%CL_PATH%" (
    echo ERROR: Visual C++ compiler not found at %CL_PATH%
    echo Please install Visual Studio 2022 with C++ workload
    exit /b 1
)

echo Found compiler: %CL_PATH%
echo.

REM Compile unified CLI
echo Compiling unified_cli.cpp...
echo.

"%CL_PATH%" /EHsc /O2 /W3 /nologo ^
    /I"%~dp0src" ^
    /I"%~dp0kernels" ^
    /I"%~dp03rdparty" ^
    /Fe"%~dp0rawrxd.exe" ^
    /Fo"%BUILD_DIR%\\" ^
    "%SRC_DIR%\unified_cli.cpp" ^
    /link /SUBSYSTEM:CONSOLE

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed
    exit /b 1
)

echo.
echo ==========================================
echo Build Successful!
echo ==========================================
echo.
echo Output: %~dp0rawrxd.exe
echo.
echo Usage:
echo   rawrxd kernel --list              List registered kernels
echo   rawrxd kernel --profile model.gguf Profile tensor sensitivity
echo   rawrxd kernel --validate --gemm   Validate fused GEMM
echo   rawrxd inspect model.gguf         Inspect GGUF model
echo   rawrxd compress --input in.gguf --output out.gguf --codec Q4_K_M
echo   rawrxd benchmark --model model.gguf
echo   rawrxd test --all                 Run all tests
echo.
echo Run 'rawrxd help' for full usage information.
echo.

endlocal
