@echo off
cd /d d:\rawrxd
echo Building test_runner_v2.exe...
C:\ProgramData\mingw64\mingw64\bin\g++.exe -O2 -std=c++17 -I. tests\test_graph_runner_v2.cpp src\core\execution\SovereignGraphRunner_v2.cpp src\core\execution\KernelRegistry.cpp src\core\execution\ReferenceBackend.cpp src\core\execution\IntrinsicsBackend.cpp -o test_runner_v2.exe 2> build_test_runner.log
if %ERRORLEVEL% EQU 0 (
    echo BUILD SUCCESS
    dir test_runner_v2.exe
) else (
    echo BUILD FAILED with error %ERRORLEVEL%
    type build_test_runner.log
)
