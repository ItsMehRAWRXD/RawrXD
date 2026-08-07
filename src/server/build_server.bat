@echo off
REM Build RawrXD Win32IDE Server
REM ============================

echo ============================================
echo RawrXD Win32IDE Server Build
echo ============================================
echo.

REM Find VS2022
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
if not exist "%VS_PATH%" set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
if not exist "%VS_PATH%" set "VS_PATH=C:\VS2022Enterprise"

if not exist "%VS_PATH%" (
    echo ERROR: Visual Studio 2022 not found!
    echo Please install VS2022 or set VS_PATH manually
    pause
    exit /b 1
)

echo Found VS2022 at: %VS_PATH%
echo.

REM Setup environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to setup VS environment
    pause
    exit /b 1
)

echo Building RawrXDWin32Server.cpp...
echo.

cl.exe /W4 /O2 /nologo /EHsc /Fe:RawrXD-Win32IDE-Server.exe RawrXDWin32Server.cpp ws2_32.lib

if errorlevel 1 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    pause
    exit /b 1
)

echo.
echo ============================================
echo BUILD SUCCESSFUL
echo ============================================
echo.
echo Output: RawrXD-Win32IDE-Server.exe
echo.
echo Usage:
echo   RawrXD-Win32IDE-Server.exe        (port 11435)
echo   RawrXD-Win32IDE-Server.exe 8080    (custom port)
echo.
echo Test with:
echo   curl http://127.0.0.1:11435/api/version
echo   curl http://127.0.0.1:11435/api/health
echo   curl http://127.0.0.1:11435/api/beacon
echo.
pause
