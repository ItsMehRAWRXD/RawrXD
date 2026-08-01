@echo off
:: Build RawrXDGateway.exe
:: Standalone build - no CMake required

echo ===========================================
echo   RawrXD Gateway Build
echo ===========================================

set SRC=RawrXDGateway_simple.cpp
set OUT=RawrXDGateway.exe
set PORT=11435

:: Find Visual Studio compiler
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist %VSWHERE% (
    for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set VS_PATH=%%i
    )
)

if exist "D:\VS2022Enterprise\VC\Tools\MSVC" (
    set MSVC_PATH=D:\VS2022Enterprise\VC\Tools\MSVC
    goto :found_msvc
)

if exist "C:\VS2022Enterprise\VC\Tools\MSVC" (
    set MSVC_PATH=C:\VS2022Enterprise\VC\Tools\MSVC
    goto :found_msvc
)

if defined VS_PATH (
    set MSVC_PATH=%VS_PATH%\VC\Tools\MSVC
    goto :found_msvc
)

echo ERROR: Could not find Visual Studio compiler
echo Please run this script from a Visual Studio Developer Command Prompt
exit /b 1

:found_msvc
:: Get latest MSVC version
for /f "delims=" %%a in ('dir /b /ad "%MSVC_PATH%" ^| sort /r') do (
    set MSVC_VER=%%a
    goto :got_ver
)
:got_ver

set CL_EXE=%MSVC_PATH%\%MSVC_VER%\bin\Hostx64\x64\cl.exe
set LINK_EXE=%MSVC_PATH%\%MSVC_VER%\bin\Hostx64\x64\link.exe

echo Found MSVC: %MSVC_VER%
echo Compiler: %CL_EXE%

:: Set up environment
set INCLUDE=%MSVC_PATH%\%MSVC_VER%\include
set LIB=%MSVC_PATH%\%MSVC_VER%\lib\x64

:: Find Windows SDK
if exist "D:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0" (
    set SDK_ROOT=D:\Program Files (x86)\Windows Kits\10
    set SDK_VER=10.0.22621.0
) else if exist "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0" (
    set SDK_ROOT=C:\Program Files (x86)\Windows Kits\10
    set SDK_VER=10.0.22621.0
) else (
    echo ERROR: Windows SDK 10.0.22621.0 not found
    exit /b 1
)

set INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\ucrt
set INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\um
set INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\shared
set LIB=%LIB%;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64
set LIB=%LIB%;%SDK_ROOT%\Lib\%SDK_VER%\um\x64

echo SDK: %SDK_VER%
echo.

:: Create build directory
if not exist "..\build" mkdir "..\build"

:: Compile
echo Compiling %SRC%...
"%CL_EXE%" /EHsc /O2 /W3 /Fe"..\build\%OUT%" /Fo"..\build\RawrXDGateway.obj" %SRC% /link ws2_32.lib

if errorlevel 1 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo ===========================================
echo   BUILD SUCCESSFUL
echo ===========================================
echo.
echo Output: ..\build\%OUT%
echo.
echo Usage:
echo   ..\build\%OUT% --port %PORT%
echo   ..\build\%OUT% --workspace D:\RawrXD
echo   ..\build\%OUT% --help
echo.
echo Then open ide_chatbot.html in your browser
echo.

exit /b 0
