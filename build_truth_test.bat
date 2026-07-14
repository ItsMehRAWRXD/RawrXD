@echo off
REM Build the integration truth test using GCC
REM This tells us what's ACTUALLY working, not what's claimed

echo ==========================================
echo Building Integration Truth Test (GCC)
echo ==========================================
echo.

set SOURCE=d:\rawrxd\tests\integration_truth_test.cpp
set OUTPUT=d:\rawrxd\build\integration_truth_test.exe

if not exist d:\rawrxd\build mkdir d:\rawrxd\build

REM Use GCC compiler
g++.exe -std=c++17 -O2 -Wall -mavx2 -o %OUTPUT% %SOURCE% -lpthread

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL: %OUTPUT%
echo.
echo Running truth test...
echo.

%OUTPUT%

exit /b %ERRORLEVEL%
