@echo off
REM ============================================================================
REM Build Script for Tensor Integration (Pure MASM + C++)
REM ============================================================================
REM Assembles all MASM modules and links with C++ bridge
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo Tensor Integration Build - Pure x64 MASM
echo ============================================================================

REM Tool paths
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe

REM Source directory
set SRC_DIR=d:\rawrxd\src\lora
set BUILD_DIR=d:\rawrxd\build\tensor_integration

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo [1/6] Assembling TensorContext.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\TensorContext.obj" "%SRC_DIR%\TensorContext.asm"
if errorlevel 1 (
    echo ERROR: TensorContext.asm assembly failed
    exit /b 1
)

echo.
echo [2/6] Assembling QKVProjection.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\QKVProjection.obj" "%SRC_DIR%\QKVProjection.asm"
if errorlevel 1 (
    echo ERROR: QKVProjection.asm assembly failed
    exit /b 1
)

echo.
echo [3/6] Assembling GemmKernel.asm...
"%ML64%" /c /W3 /nologo /Zi /Fo "%BUILD_DIR%\GemmKernel.obj" "%SRC_DIR%\GemmKernel.asm"
if errorlevel 1 (
    echo ERROR: GemmKernel.asm assembly failed
    exit /b 1
)

echo.
echo [4/6] Compiling TensorBridge.cpp...
"%CL%" /c /O2 /std:c++17 /arch:AVX2 /nologo /Fo "%BUILD_DIR%\TensorBridge.obj" "%SRC_DIR%\TensorBridge.hpp"
if errorlevel 1 (
    echo ERROR: TensorBridge.hpp compilation failed
    exit /b 1
)

echo.
echo [5/6] Compiling test harness...
"%CL%" /c /O2 /std:c++17 /arch:AVX2 /nologo /Fo "%BUILD_DIR%\test_tensor_integration.obj" "%SRC_DIR%\test_tensor_integration.cpp"
if errorlevel 1 (
    echo ERROR: Test harness compilation failed
    exit /b 1
)

echo.
echo [6/6] Linking...
"%LINK%" /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /LARGEADDRESSAWARE /OUT:"%BUILD_DIR%\test_tensor_integration.exe" ^
    "%BUILD_DIR%\TensorContext.obj" ^
    "%BUILD_DIR%\QKVProjection.obj" ^
    "%BUILD_DIR%\GemmKernel.obj" ^
    "%BUILD_DIR%\TensorBridge.obj" ^
    "%BUILD_DIR%\test_tensor_integration.obj" ^
    kernel32.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ============================================================================
echo BUILD SUCCESSFUL
echo ============================================================================
echo Output: %BUILD_DIR%\test_tensor_integration.exe
echo ============================================================================

endlocal