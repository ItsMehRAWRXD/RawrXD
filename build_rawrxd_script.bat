@echo off
:: Build RawrXD_Script.exe - JavaScript Runtime Orchestrator

echo Building RawrXD_Script.exe...
echo.

:: Setup VS environment
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment
    exit /b 1
)

:: Create output directory
if not exist "d:\rawrxd\build\bin" mkdir "d:\rawrxd\build\bin"

:: Build with CMake
cd /d d:\rawrxd
cmake --build build --target RawrXD_Script --config Release
if errorlevel 1 (
    echo ERROR: CMake build failed
    exit /b 1
)

echo.
echo Build complete!
echo Executable: d:\rawrxd\build\bin\RawrXD_Script.exe
