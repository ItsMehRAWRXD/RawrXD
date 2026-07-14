@echo off
REM =============================================================================
REM RawRamXD Phase 7C Build Script (GCC/MinGW)
REM Predictive Memory Intelligence - Learning-Based Policy Refinement
REM =============================================================================

setlocal enabledelayedexpansion

REM Configuration
set SOURCE_DIR=%~dp0
set BUILD_DIR=%SOURCE_DIR%\build_phase7c
set OUTPUT_NAME=RawRamXD_Phase7C_PredictiveTest

REM Compiler settings
set CXX=g++.exe
set CXXFLAGS=-std=c++17 -O2 -mavx2 -Wall -Wextra -D_CRT_SECURE_NO_WARNINGS
set INCLUDES=-I"%SOURCE_DIR%"
set LIBS=-lpthread

REM Source files
set SOURCES=%SOURCE_DIR%\RawRamXD_Phase7C_PredictiveMemory.cpp %SOURCE_DIR%\RawRamXD_Phase7C_PredictiveTest.cpp

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo =============================================================================
echo RawRamXD Phase 7C: Predictive Memory Intelligence
echo Build Configuration (GCC/MinGW)
echo =============================================================================
echo Source Dir: %SOURCE_DIR%
echo Build Dir:  %BUILD_DIR%
echo Output:     %OUTPUT_NAME%.exe
echo.

REM Clean previous build
echo Cleaning previous build...
if exist "%BUILD_DIR%\*.o" del /Q "%BUILD_DIR%\*.o"
if exist "%BUILD_DIR%\%OUTPUT_NAME%.exe" del /Q "%BUILD_DIR%\%OUTPUT_NAME%.exe"

REM Compile
echo.
echo Compiling Phase 7C sources...
echo =============================================================================

%CXX% %CXXFLAGS% %INCLUDES% -o "%BUILD_DIR%\%OUTPUT_NAME%.exe" %SOURCES% %LIBS%

if errorlevel 1 (
    echo.
    echo =============================================================================
    echo BUILD FAILED
echo =============================================================================
    exit /b 1
)

echo.
echo =============================================================================
echo BUILD SUCCESSFUL
echo =============================================================================
echo Output: %BUILD_DIR%\%OUTPUT_NAME%.exe
echo.

REM Run tests
echo Running Phase 7C Acceptance Gates C1-C6...
echo =============================================================================
cd /d "%BUILD_DIR%"
%OUTPUT_NAME%.exe

set TEST_RESULT=%ERRORLEVEL%

echo.
echo =============================================================================
if %TEST_RESULT%==0 (
    echo ALL GATES PASSED - Phase 7C is operational!
) else (
    echo SOME GATES FAILED - Review output above
)
echo =============================================================================

exit /b %TEST_RESULT%
