@echo off
REM Build script for Deep2Engine

cd /d "%~dp0"

echo ====================================================
echo       DEEP2ENGINE BUILD PIPELINE
echo ====================================================

if not exist build (
    mkdir build
)

cd build

echo [CMAKE] Configuring project...
cmake .. -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (
    echo [ERROR] CMake configuration failed
    exit /b 1
)

echo [BUILD] Compiling...
cmake --build . --config Release
if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)

echo.
echo ====================================================
echo [SUCCESS] Build complete! Executable at:
echo    build\bin\Deep2Engine_Benchmark.exe
echo ====================================================