@echo off
REM Build Deep2 Gateway Runtime Certification
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
echo Building Deep2_Gateway_Runtime_Certification.exe...
echo.

REM Build the certification test
cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /I. /I.. /I..\.. ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /Fe:Deep2_Gateway_Runtime_Certification.exe ^
    Deep2_Gateway_Runtime_Certification.cpp ^
    deep2_http_gateway.cpp ^
    mcp_bridge.cpp ^
    /link /SUBSYSTEM:CONSOLE ws2_32.lib winhttp.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b %ERRORLEVEL%
)

echo.
echo ==========================================
echo BUILD SUCCESSFUL
echo ==========================================
dir Deep2_Gateway_Runtime_Certification.exe
echo.
echo Run with:
echo   Deep2_Gateway_Runtime_Certification.exe
echo ==========================================
