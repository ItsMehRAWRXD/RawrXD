@echo off
cd /d d:\src\benchmark

echo Current directory: %CD%
echo.

echo Building standalone benchmark...
g++ -std=c++17 -O3 -mavx2 -mfma -o standalone_bench.exe standalone_bench.cpp 2>&1

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Build failed with error code %ERRORLEVEL%
    pause
    exit /b 1
)

echo.
echo Build successful!
echo.
echo Running benchmark...
standalone_bench.exe

pause
