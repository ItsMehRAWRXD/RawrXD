@echo off
REM ============================================================================
REM GGUF Transformer Integration Build Script
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set OUT_DIR=build
set CXX=g++.exe
set CXXFLAGS=-std=c++17 -O3 -Wall -Wextra -march=native
set INCLUDES=-I. -I../../rawrxd/sovereign

REM Source files
set SOURCES=transformer_layer_runtime.cpp gguf_transformer_integration.cpp test_gguf_integration.cpp
set OUTPUT=%OUT_DIR%\test_gguf_integration.exe

echo ============================================================================
echo Building GGUF Transformer Integration
echo ============================================================================
echo.

REM Create output directory
if not exist %OUT_DIR% mkdir %OUT_DIR%

REM Compile
echo Compiling...
%CXX% %CXXFLAGS% %INCLUDES% %SOURCES% -o %OUTPUT% -L../../rawrxd/sovereign/build -lgguf_adapter
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo.
echo ============================================================================
echo Build Successful
echo ============================================================================
echo.
echo Executable: %OUTPUT%
echo.
echo Usage: %OUTPUT% ^<gguf_file^> [info^|layers^|inference^|bench]
echo.

endlocal
