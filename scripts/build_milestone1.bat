@echo off
REM Build script for Milestone 1: C++ -> MASM -> JsValue integration
REM Uses MinGW gcc for C++ and MSVC ml64 for assembly

setlocal EnableDelayedExpansion

echo ============================================
echo RawrXD-Script Milestone 1 Build
echo ============================================
echo.

REM Configuration
set "ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set "CC=gcc"
set "CXX=g++"
set "SRC_DIR=..\src\script"
set "BUILD_DIR=..\build\milestone1"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/3] Assembling interpreter_milestone1.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\interpreter.obj" "%SRC_DIR%\masm\interpreter_milestone1.asm" 2>&1
if !ERRORLEVEL! neq 0 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo [2/3] Compiling runtime_minimal.cpp...
"%CXX%" -c -std=c++17 -Wall -O2 -o "%BUILD_DIR%\runtime_minimal.o" "%SRC_DIR%\runtime\runtime_minimal.cpp" 2>nul
if !ERRORLEVEL! neq 0 (
    echo ERROR: Runtime compilation failed
    exit /b 1
)

echo [3/3] Compiling milestone1_basic_execution.cpp...
"%CXX%" -std=c++17 -Wall -O2 -o "%BUILD_DIR%\milestone1_test.exe" ^
    "%SRC_DIR%\tests\integration\milestone1_basic_execution.cpp" ^
    "%BUILD_DIR%\runtime_minimal.o" ^
    "%BUILD_DIR%\interpreter.obj" ^
    -static 2>nul
if !ERRORLEVEL! neq 0 (
    echo ERROR: Test compilation failed
    exit /b 1
)

echo.
echo ============================================
echo Build successful!
echo ============================================
echo.
echo To run tests:
echo   %BUILD_DIR%\milestone1_test.exe
echo.

endlocal
