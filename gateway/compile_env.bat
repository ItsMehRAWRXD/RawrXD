@echo off
cd /d d:\RawrXD\gateway

:: Set up MSVC environment
set MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231
set SDK_ROOT=C:\Program Files (x86)\Windows Kits\10
set SDK_VER=10.0.22621.0

set INCLUDE=%MSVC_ROOT%\include
set INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\ucrt
set INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\um
set INCLUDE=%INCLUDE%;%SDK_ROOT%\Include\%SDK_VER%\shared

set LIB=%MSVC_ROOT%\lib\x64
set LIB=%LIB%;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64
set LIB=%LIB%;%SDK_ROOT%\Lib\%SDK_VER%\um\x64

echo Compiling RawrXDGateway...
"%MSVC_ROOT%\bin\Hostx64\x64\cl.exe" /EHsc /std:c++17 /O2 /W3 /Fed:\RawrXD\build\RawrXDGateway.exe /Fod:\RawrXD\build\RawrXDGateway.obj RawrXDGateway_simple.cpp /link ws2_32.lib
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo.
echo ===========================================
echo BUILD SUCCESS
echo ===========================================
echo Output: d:\RawrXD\build\RawrXDGateway.exe
echo.
echo Usage:
echo   d:\RawrXD\build\RawrXDGateway.exe --port 11435
echo   d:\RawrXD\build\RawrXDGateway.exe --workspace D:\RawrXD
echo.
