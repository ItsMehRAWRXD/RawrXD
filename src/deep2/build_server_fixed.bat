@echo off
REM Build Deep2 Complete API Server - Fixed
REM ========================================

set "VSPATH=C:\VS2022Enterprise\VC\Auxiliary\Build"
if not exist "%VSPATH%\vcvars64.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build"
)
if not exist "%VSPATH%\vcvars64.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
)

echo Using VS path: %VSPATH%
call "%VSPATH%\vcvars64.bat" 2>nul
if errorlevel 1 (
    echo ERROR: Could not find vcvars64.bat
    echo Please install Visual Studio 2022 with C++ workload
    pause
    exit /b 1
)

echo Building Deep2 Complete API Server...
echo.

cl.exe /W3 /O2 /nologo /EHsc /std:c++17 /Fe:Deep2APIServer.exe Deep2APIServer_Complete.cpp ws2_32.lib /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um" /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared"

if errorlevel 1 (
    echo.
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Build complete: Deep2APIServer.exe
echo ==========================================
pause
