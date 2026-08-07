@echo off
REM Manual build script for witness_system_test
REM Run this from Developer Command Prompt for VS 2022

cd /d d:\rawrxd

REM Set up MSVC environment
if not defined VSCMD_VER (
    echo ERROR: Please run this from Developer Command Prompt for VS 2022
    echo.
    echo To open Developer Command Prompt:
    echo   Start Menu -> Visual Studio 2022 -> Developer Command Prompt
    pause
    exit /b 1
)

echo Building witness_system_test...
cl /std:c++17 /EHsc /O2 /I include ^
    src\validation\witness_system_test.cpp ^
    src\core\inference_witness.cpp ^
    /Fe:build-ninja\bin\witness_system_test.exe ^
    /Fo:build-ninja\witness_system_test.obj

if %ERRORLEVEL% == 0 (
    echo.
    echo Build successful!
    echo.
    echo Running witness_system_test...
    build-ninja\bin\witness_system_test.exe
    echo.
    echo Witness artifact should be in: evidence\inference_witness_*.json
) else (
    echo.
    echo Build failed!
)

pause
