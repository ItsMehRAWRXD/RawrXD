@echo off
REM Build all benchmarks using VS2022 tools
setlocal

REM Set up VS environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo Failed to set up VS environment
    exit /b 1
)

echo VS Environment set up successfully
echo.

REM Create build directory
if not exist build mkdir build

echo Building MASM Hello World...
ml64 /c /W3 /nologo /Fo build\masm_hello_world.obj masm_hello_world.asm
if errorlevel 1 goto :error

link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /OUT:build\masm_hello_world.exe build\masm_hello_world.obj kernel32.lib
if errorlevel 1 goto :error
echo   OK: masm_hello_world.exe
echo.

echo Building C++ Hello World...
cl /O2 /arch:AVX2 /EHsc /MT /std:c++17 /W3 /nologo /Fe:build\cpp_hello_world.exe cpp_hello_world.cpp
if errorlevel 1 goto :error
echo   OK: cpp_hello_world.exe
echo.

echo Building Swarm TPS Benchmark...
cl /O2 /arch:AVX2 /EHsc /MT /std:c++17 /W3 /nologo /Fe:build\swarm_tps_benchmark.exe swarm_tps_benchmark.cpp
if errorlevel 1 goto :error
echo   OK: swarm_tps_benchmark.exe
echo.

echo Building Chat TPS Benchmark...
cl /O2 /arch:AVX2 /EHsc /MT /std:c++17 /W3 /nologo /Fe:build\chat_tps_benchmark.exe chat_tps_benchmark.cpp
if errorlevel 1 goto :error
echo   OK: chat_tps_benchmark.exe
echo.

echo Building Agentic TPS Benchmark...
cl /O2 /arch:AVX2 /EHsc /MT /std:c++17 /W3 /nologo /Fe:build\agentic_tps_benchmark.exe agentic_tps_benchmark.cpp
if errorlevel 1 goto :error
echo   OK: agentic_tps_benchmark.exe
echo.

echo ================================================================================
echo Build Complete
echo ================================================================================
echo.
echo Executables in build\ directory:
dir build\*.exe /b
echo.
goto :end

:error
echo.
echo BUILD FAILED
echo.
exit /b 1

:end
endlocal
