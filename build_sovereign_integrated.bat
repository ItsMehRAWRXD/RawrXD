@echo off
REM Build script for RawrXD Sovereign Runtime v1.0-ALPHA (Integrated)
REM Maximum Compression: All subsystems wired to real implementations

echo ========================================
echo  RawrXD Sovereign Runtime v1.0-ALPHA
echo  INTEGRATED BUILD
echo ========================================
echo.

set BUILD_DIR=build-ninja-sovereign
set CMAKE_GENERATOR=Ninja

REM Check for Ninja
where ninja >nul 2>nul
if errorlevel 1 (
    echo ERROR: Ninja not found in PATH
    echo Please install Ninja or add it to PATH
    exit /b 1
)

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo [1/4] Configuring with CMake...
cmake -B %BUILD_DIR% -G %CMAKE_GENERATOR% ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DRAWRXD_PRODUCTION_STRIP_STUB_SOURCES=OFF ^
    -DRAWRXD_BUILD_WIN32IDE=OFF ^
    -DRAWRXD_BUILD_CLI=OFF

if errorlevel 1 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

echo.
echo [2/4] Building RawrXD-Sovereign-Integrated...
ninja -C %BUILD_DIR% RawrXD-Sovereign-Integrated

if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo [3/4] Verifying executable...
if exist %BUILD_DIR%\bin\RawrXD-Sovereign-Integrated.exe (
    echo SUCCESS: Executable built at %BUILD_DIR%\bin\RawrXD-Sovereign-Integrated.exe
    %BUILD_DIR%\bin\RawrXD-Sovereign-Integrated.exe --help
) else (
    echo ERROR: Executable not found
    exit /b 1
)

echo.
echo ========================================
echo  BUILD COMPLETE
echo ========================================
echo.
echo Usage:
echo   %BUILD_DIR%\bin\RawrXD-Sovereign-Integrated.exe --model ^<path^> --prompt "text" --validate
echo.
echo Example:
echo   %BUILD_DIR%\bin\RawrXD-Sovereign-Integrated.exe --model models\\phi3-mini.gguf --prompt "Hello" --max-tokens 50 --validate
echo.
