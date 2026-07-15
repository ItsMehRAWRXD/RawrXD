@echo off
cd /d d:\src\benchmark

echo Building standalone benchmark...
g++ -std=c++17 -O3 -mavx2 -mfma -o standalone_bench.exe standalone_bench.cpp

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

echo.
echo Running benchmark...
standalone_bench.exe

pause
