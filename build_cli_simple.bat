@echo off
REM Simple build script for RawrXD Unified CLI (Standalone)
REM This version doesn't require full kernel headers

setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD Unified CLI Build (Standalone)
echo ==========================================
echo.

set SRC=%~dp0src\cli\unified_cli_standalone.cpp
set OUT=%~dp0rawrxd.exe

REM Try to find cl.exe
set "CL_PATH="
for %%p in (
    "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
) do (
    if exist %%p (
        set "CL_PATH=%%p"
        goto :found_cl
    )
)

REM Try to find via vswhere
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe" (
        set "CL_PATH=%%i\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe"
        goto :found_cl
    )
    if exist "%%i\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" (
        set "CL_PATH=%%i\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe"
        goto :found_cl
    )
)

:found_cl
if not defined CL_PATH (
    echo ERROR: Could not find Visual C++ compiler (cl.exe)
    echo Please install Visual Studio 2022 with C++ workload
    exit /b 1
)

echo Found compiler: %CL_PATH%
echo.

REM Check source file
if not exist "%SRC%" (
    echo ERROR: Source file not found: %SRC%
    exit /b 1
)

REM Compile
echo Compiling unified_cli_standalone.cpp...
echo.

"%CL_PATH%" /EHsc /O2 /W3 /nologo /std:c++17 /Fe"%OUT%" "%SRC%"

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed
    exit /b 1
)

echo.
echo ==========================================
echo Build Successful!
echo ==========================================
echo.
echo Output: %OUT%
echo.
echo Quick Start:
echo   rawrxd help
echo   rawrxd kernel --list
echo   rawrxd kernel --validate --gemm
echo   rawrxd test --all
echo.

endlocal
