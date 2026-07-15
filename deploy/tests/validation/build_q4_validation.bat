@echo off
REM build_q4_validation.bat
REM Build Q4_0 validation test using MinGW

echo Building Q4_0 validation...

set SRC=d:\rawrxd-ci-bootstrap\tests\validation\q4_0_validation.cpp
set OUT=d:\rawrxd-ci-bootstrap\tests\validation\q4_0_validation.exe

C:\ProgramData\mingw64\mingw64\bin\g++.exe -O2 -Wall -std=c++17 -o %OUT% %SRC%

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)

echo Build successful: %OUT%
exit /b 0
