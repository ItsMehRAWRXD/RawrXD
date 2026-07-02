@echo off
REM RawrXD Native Sidecar Build Script
REM King style - One command to build everything

echo ========================================
echo   RawrXD Native Sidecar Build
echo ========================================
echo.

set BUILD_DIR=build
set INSTALL_DIR=..\..\vscode-extension\native

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd %BUILD_DIR%

REM Configure with CMake
echo [1/4] Configuring with CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (
    echo [ERROR] CMake configuration failed
    exit /b 1
)

REM Build
echo.
echo [2/4] Building...
cmake --build . --config Release --parallel
if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)

REM Verify binary exists
echo.
echo [3/4] Verifying binary...
if not exist bin\Release\RawrXD_Sidecar.exe (
    echo [ERROR] Binary not found at expected location
    exit /b 1
)

REM Copy to extension directory
echo.
echo [4/4] Installing to extension...
if not exist %INSTALL_DIR% mkdir %INSTALL_DIR%
copy bin\Release\RawrXD_Sidecar.exe %INSTALL_DIR%\
if errorlevel 1 (
    echo [ERROR] Installation failed
    exit /b 1
)

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo Binary: %INSTALL_DIR%\RawrXD_Sidecar.exe
echo.
echo Next steps:
echo   1. Test the bridge: npm run test:bridge
echo   2. Launch VSCode extension
echo   3. Run command: RawrXD: Start Agent Mode
echo ========================================

cd ..
