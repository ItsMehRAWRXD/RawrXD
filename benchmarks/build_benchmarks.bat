@echo off
REM Build script for RawrXD TPS Benchmarks
REM Uses VS2022 Enterprise tools

setlocal enabledelayedexpansion

REM Configuration
set "BENCH_DIR=%~dp0"
set "BUILD_DIR=%BENCH_DIR%build"
set "VS_TOOLS=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
set "ML64=%VS_TOOLS%\bin\Hostx64\x64\ml64.exe"
set "CL=%VS_TOOLS%\bin\Hostx64\x64\cl.exe"
set "LINK=%VS_TOOLS%\bin\Hostx64\x64\link.exe"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo ================================================================================
echo RawrXD TPS Benchmark Build System
echo ================================================================================
echo.

REM Check for tools
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at %ML64%
    exit /b 1
)

if not exist "%CL%" (
    echo ERROR: cl.exe not found at %CL%
    exit /b 1
)

echo Found build tools:
echo   ML64: %ML64%
echo   CL:   %CL%
echo.

REM Build MASM Hello World
echo [1/5] Building MASM Hello World...
"%ML64%" /c /W3 /nologo /Fo"%BUILD_DIR%\masm_hello_world.obj" "%BENCH_DIR%\masm_hello_world.asm"
if errorlevel 1 (
    echo FAILED to assemble masm_hello_world.asm
    exit /b 1
)

"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /OUT:"%BUILD_DIR%\masm_hello_world.exe" /MACHINE:X64 /LIBPATH:"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" "%BUILD_DIR%\masm_hello_world.obj" kernel32.lib
if errorlevel 1 (
    echo FAILED to link masm_hello_world.exe
    exit /b 1
)
echo   OK: %BUILD_DIR%\masm_hello_world.exe
echo.

REM Build C++ benchmarks
set "CXXFLAGS=/O2 /arch:AVX2 /EHsc /MT /std:c++17 /W3 /nologo"
set "LDFLAGS=/SUBSYSTEM:CONSOLE"

echo [2/5] Building C++ Hello World...
"%CL%" %CXXFLAGS% /Fe"%BUILD_DIR%\cpp_hello_world.exe" "%BENCH_DIR%\cpp_hello_world.cpp"
if errorlevel 1 (
    echo FAILED to build cpp_hello_world.cpp
    exit /b 1
)
echo   OK: %BUILD_DIR%\cpp_hello_world.exe
echo.

echo [3/5] Building Swarm TPS Benchmark...
"%CL%" %CXXFLAGS% /Fe"%BUILD_DIR%\swarm_tps_benchmark.exe" "%BENCH_DIR%\swarm_tps_benchmark.cpp"
if errorlevel 1 (
    echo FAILED to build swarm_tps_benchmark.cpp
    exit /b 1
)
echo   OK: %BUILD_DIR%\swarm_tps_benchmark.exe
echo.

echo [4/5] Building Chat TPS Benchmark...
"%CL%" %CXXFLAGS% /Fe"%BUILD_DIR%\chat_tps_benchmark.exe" "%BENCH_DIR%\chat_tps_benchmark.cpp"
if errorlevel 1 (
    echo FAILED to build chat_tps_benchmark.cpp
    exit /b 1
)
echo   OK: %BUILD_DIR%\chat_tps_benchmark.exe
echo.

echo [5/5] Building Agentic TPS Benchmark...
"%CL%" %CXXFLAGS% /Fe"%BUILD_DIR%\agentic_tps_benchmark.exe" "%BENCH_DIR%\agentic_tps_benchmark.cpp"
if errorlevel 1 (
    echo FAILED to build agentic_tps_benchmark.cpp
    exit /b 1
)
echo   OK: %BUILD_DIR%\agentic_tps_benchmark.exe
echo.

echo ================================================================================
echo Build Complete
echo ================================================================================
echo.
echo Executables:
for %%f in ("%BUILD_DIR%\*.exe") do (
    echo   %%~nxf
)
echo.
echo To run benchmarks:
echo   cd %BUILD_DIR%
echo   for %%f in (*.exe) do %%f
echo.
echo Or use PowerShell:
echo   powershell -ExecutionPolicy Bypass -File "%BENCH_DIR%\run_all_benchmarks.ps1"
echo.

endlocal
