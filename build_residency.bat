@echo off
REM =============================================================================
REM Build Elastic Residency Benchmark
REM =============================================================================

echo Building Elastic Residency Benchmark...
echo.

set "SOURCE_DIR=%~dp0"
set "BUILD_DIR=%SOURCE_DIR%build_residency"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

cd /d "%BUILD_DIR%"

REM Configure with CMake
echo [1/3] Configuring...
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DHAS_CUDA=OFF "%SOURCE_DIR%" 2>&1
if errorlevel 1 (
    echo [!] CMake configuration failed
    exit /b 1
)

REM Build
echo [2/3] Building...
ninja -j4 2>&1
if errorlevel 1 (
    echo [!] Build failed
    exit /b 1
)

echo [3/3] Done!
echo.
echo Binary: %BUILD_DIR%\ElasticResidencyBench.exe
echo.
echo Run with:
echo   ElasticResidencyBench.exe
echo   ElasticResidencyBench.exe --vram 16 --duration 30

cd /d "%SOURCE_DIR%"