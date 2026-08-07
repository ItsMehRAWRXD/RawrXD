@echo off
REM Build Deep2 HTTP Server with Windows SDK paths
@echo off
setlocal

REM Find VS2022
set "VSPATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
)
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    set "VSPATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
)

if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)

echo Found VS2022 at: %VSPATH%

REM Call vcvarsall and capture environment
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

cd /d "d:\rawrxd\src\deep2"

echo.
echo Building Deep2Server_Minimal.exe...
echo.

REM Find Windows SDK
set "SDKPATH=C:\Program Files (x86)\Windows Kits\10"
if not exist "%SDKPATH%\Include\10.0.22621.0\um\windows.h" (
    set "SDKPATH=C:\Program Files (x86)\Windows Kits\10"
)

cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /I. ^
    /I"%SDKPATH%\Include\10.0.22621.0\um" ^
    /I"%SDKPATH%\Include\10.0.22621.0\shared" ^
    /I"%SDKPATH%\Include\10.0.22621.0\ucrt" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /Fe:Deep2Server_Minimal.exe ^
    Deep2Server_Minimal.cpp ^
    /link /SUBSYSTEM:CONSOLE ws2_32.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo ==========================================
echo BUILD SUCCESSFUL
echo ==========================================
dir Deep2Server_Minimal.exe
echo.
echo Test with:
echo   Deep2Server_Minimal.exe ^&
echo   curl http://127.0.0.1:11436/health
echo ==========================================
