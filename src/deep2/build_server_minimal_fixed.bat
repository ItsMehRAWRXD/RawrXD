@echo off
REM Build Deep2 Minimal HTTP Server - Fixed Path
REM =============================================

set "VSPATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build"
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
    pause
    exit /b 1
)

echo Building Deep2 Minimal HTTP Server...
echo.

set SRC_DIR=%~dp0
set BUILD_DIR=%SRC_DIR%\smoketest_build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

cl.exe /nologo /W4 /O2 /arch:AVX2 /EHsc /std:c++20 ^
    /I"%SRC_DIR%" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /Fe"%BUILD_DIR%\Deep2Server_Minimal.exe" ^
    "%SRC_DIR%\Deep2Server_Minimal.cpp" ^
    /link /SUBSYSTEM:CONSOLE ws2_32.lib

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ==========================================
echo BUILD SUCCESSFUL
echo Executable: %BUILD_DIR%\Deep2Server_Minimal.exe
echo ==========================================
echo.
echo To run:
echo   %BUILD_DIR%\Deep2Server_Minimal.exe
echo.
echo Test endpoints:
echo   curl http://127.0.0.1:11436/health
echo   curl http://127.0.0.1:11436/api/version
echo   curl http://127.0.0.1:11436/api/phases
echo ==========================================
pause
