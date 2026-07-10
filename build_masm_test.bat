@echo off
REM Build script for MASM Backend Test (Phase 7C.2)
REM Uses MinGW-w64 GCC

set GPP=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set SRC_DIR=src\core\execution
set TEST_DIR=tests
set ASM_DIR=..\src\asm

echo ===========================================
echo Building MASM Backend Test
echo Phase 7C.2 - MASM Integration
echo ===========================================
echo.

REM Check compiler
if not exist "%GPP%" (
    echo ERROR: MinGW g++ not found at %GPP%
    exit /b 1
)

echo Compiler: %GPP%
echo.

REM Compile source files
echo Compiling source files...

REM MASM Backend
echo   MASMBackend.cpp...
"%GPP%" -c -O2 -std=c++17 -I. %SRC_DIR%\MASMBackend.cpp -o MASMBackend.o 2>&1
if errorlevel 1 (
    echo FAILED: MASMBackend.cpp
    exit /b 1
)

REM Reference Backend
echo   ReferenceBackend.cpp...
"%GPP%" -c -O2 -std=c++17 -I. %SRC_DIR%\ReferenceBackend.cpp -o ReferenceBackend.o 2>&1
if errorlevel 1 (
    echo FAILED: ReferenceBackend.cpp
    exit /b 1
)

REM Kernel Registry
echo   KernelRegistry.cpp...
"%GPP%" -c -O2 -std=c++17 -I. %SRC_DIR%\KernelRegistry.cpp -o KernelRegistry.o 2>&1
if errorlevel 1 (
    echo FAILED: KernelRegistry.cpp
    exit /b 1
)

REM Test file
echo   test_masm_backend.cpp...
"%GPP%" -c -O2 -std=c++17 -I. %TEST_DIR%\test_masm_backend.cpp -o test_masm_backend.o 2>&1
if errorlevel 1 (
    echo FAILED: test_masm_backend.cpp
    exit /b 1
)

echo.
echo Linking...
"%GPP%" -O2 -std=c++17 MASMBackend.o ReferenceBackend.o KernelRegistry.o test_masm_backend.o -o test_masm_backend.exe 2>&1
if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo.
echo ===========================================
echo Build SUCCESSFUL
echo ===========================================
echo.
echo Running test...
test_masm_backend.exe

exit /b 0
