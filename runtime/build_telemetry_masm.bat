@echo off
REM Build script for MASM Telemetry Core
REM Requires: Visual Studio 2022 (ml64.exe)

echo Building MASM Telemetry Core...

REM Set up Visual Studio environment
set VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717
set ML64=%VS_PATH%\bin\Hostx64\x64\ml64.exe
set LINK=%VS_PATH%\bin\Hostx64\x64\link.exe

REM Check tools exist
if not exist "%ML64%" (
    echo ERROR: ml64.exe not found at %ML64%
    exit /b 1
)

if not exist "%LINK%" (
    echo ERROR: link.exe not found at %LINK%
    exit /b 1
)

REM Assemble
echo Assembling telemetry_masm.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo telemetry_masm.obj telemetry_masm.asm
if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

REM Create static library
echo Creating static library...
"%LINK%" /lib /nologo /out:telemetry_masm.lib telemetry_masm.obj
if errorlevel 1 (
    echo ERROR: Library creation failed
    exit /b 1
)

echo.
echo Build successful!
echo   telemetry_masm.obj - Object file
echo   telemetry_masm.lib - Static library
echo.
echo To use in C++:
echo   #include "telemetry_masm_bridge.hpp"
echo   Link with telemetry_masm.lib

exit /b 0
