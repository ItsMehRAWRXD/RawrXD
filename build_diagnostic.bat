@echo off
REM Build script for Phase 7 Diagnostic Tool

set GPP=C:\ProgramData\mingw64\mingw64\bin\g++.exe

echo ===========================================
echo Building Phase 7 Diagnostic Tool
echo ===========================================
echo.

if not exist "%GPP%" (
    echo ERROR: MinGW g++ not found at %GPP%
    exit /b 1
)

echo Compiling diagnose_kernel_loading.cpp...
"%GPP%" -O2 -std=c++17 -I. diagnose_kernel_loading.cpp -o diagnose_kernel_loading.exe 2>&1

if errorlevel 1 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo ===========================================
echo BUILD SUCCESSFUL
echo ===========================================
echo.
echo Running diagnostic...
echo.
diagnose_kernel_loading.exe

exit /b 0
