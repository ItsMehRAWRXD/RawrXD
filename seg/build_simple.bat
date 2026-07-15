@echo off
REM ============================================================================
REM Simple Transformer Runtime Build Script (No CMake)
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set OUT_DIR=build
set CXX=cl.exe
set CXXFLAGS=/std:c++17 /O2 /W4 /EHsc /arch:AVX2 /D_CRT_SECURE_NO_WARNINGS
set INCLUDES=/I.
set SOURCES=transformer_layer_runtime.cpp test_simple.cpp
set OUTPUT=%OUT_DIR%\test_transformer.exe

REM Create output directory
if not exist %OUT_DIR% mkdir %OUT_DIR%

echo ============================================================================
echo Building Transformer Runtime
echo ============================================================================
echo Compiler: %CXX%
echo Flags: %CXXFLAGS%
echo Output: %OUTPUT%
echo.

REM Compile
echo Compiling...
%CXX% %CXXFLAGS% %INCLUDES% %SOURCES% /Fe:%OUTPUT%
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo.
echo ============================================================================
echo Build Successful
echo ============================================================================
echo.
echo Run with: %OUTPUT%
echo.

endlocal
