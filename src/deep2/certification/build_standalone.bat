@echo off
REM ============================================================================
REM Deep2 Gateway Runtime Certification - Standalone Build
REM Zero Ship dependencies. C++20 compatible. Win32-native only.
REM ============================================================================

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

cd /d "%~dp0"

echo.
echo ============================================================================
echo Building Deep2_Gateway_Runtime_Certification.exe (Standalone)echo ============================================================================
echo.

REM Find Windows SDK
set "SDKPATH=C:\Program Files (x86)\Windows Kits\10"
if not exist "%SDKPATH%\Include\10.0.22621.0\um\windows.h" (
    echo WARNING: Windows SDK not found at expected location
)

REM Build with C++20, no exceptions, no RTTI, minimal dependencies
cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /GR- ^
    /I"%SDKPATH%\Include\10.0.22621.0\um" ^
    /I"%SDKPATH%\Include\10.0.22621.0\shared" ^
    /I"%SDKPATH%\Include\10.0.22621.0\ucrt" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /DWIN32_LEAN_AND_MEAN ^
    /DNDEBUG ^
    /Fe:Deep2_Gateway_Runtime_Certification.exe ^
    Deep2_Cert_Main.cpp ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X64 ^
    /LIBPATH:"%SDKPATH%\Lib\10.0.22621.0\um\x64" ^
    /LIBPATH:"%SDKPATH%\Lib\10.0.22621.0\ucrt\x64" ^
    winhttp.lib ws2_32.lib kernel32.lib user32.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================================
echo BUILD SUCCESSFUL
echo ============================================================================
dir Deep2_Gateway_Runtime_Certification.exe
echo.
echo Run with:
echo   Deep2_Gateway_Runtime_Certification.exe
echo.
echo Prerequisites:
echo   - Deep2 HTTP Gateway must be running on port 11435
echo   - Or start with: start_deep2_server.bat
echo ============================================================================
