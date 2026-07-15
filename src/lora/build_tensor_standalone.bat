@echo off
REM ============================================================================
REM Build Script for Tensor Abstraction (Standalone Test)
REM ============================================================================
REM Assembles TensorContext.asm and links with standalone test
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo Tensor Abstraction Build - Pure x64 MASM
echo ============================================================================

REM Tool paths (using VS2022 BuildTools)
set ML64="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe"
set LINK="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"
set CL="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"

REM Source directory
set SRC_DIR=d:\rawrxd\src\lora
set BUILD_DIR=d:\rawrxd\build\tensor_standalone

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo [1/3] Assembling TensorContext.asm...
%ML64% /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\TensorContext.obj" "%SRC_DIR%\TensorContext.asm"
if errorlevel 1 (
    echo ERROR: TensorContext.asm assembly failed
    exit /b 1
)

echo.
echo [2/3] Compiling test_tensor_standalone.cpp...
%CL% /c /O2 /std:c++17 /arch:AVX2 /nologo /Fo "%BUILD_DIR%\test_tensor_standalone.obj" "%SRC_DIR%\test_tensor_standalone.cpp"
if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)

echo.
echo [3/3] Linking...
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE /OUT:"%BUILD_DIR%\test_tensor_standalone.exe" ^
    "%BUILD_DIR%\TensorContext.obj" ^
    "%BUILD_DIR%\test_tensor_standalone.obj" ^
    kernel32.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ============================================================================
echo BUILD SUCCESSFUL
echo ============================================================================
echo Output: %BUILD_DIR%\test_tensor_standalone.exe
echo ============================================================================

endlocal