@echo off
REM =============================================================================
REM Build-Phase9-RealWorld-MinGW.bat
REM Build script for RawRamXD Phase 9: Real-World Integration (MinGW)
REM =============================================================================

setlocal enabledelayedexpansion

echo =================================================================
echo RawRamXD Phase 9: Real-World Integration Build (MinGW)
echo =================================================================
echo.

set "PROJECT_ROOT=D:\rawrxd"
set "BUILD_DIR=%PROJECT_ROOT%\build_phase9"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Build Configuration:
echo   Compiler: MinGW g++
echo   Platform: x64
echo   Build Dir: %BUILD_DIR%
echo.

REM Compiler flags
set "COMMON_FLAGS=-std=c++17 -O2 -Wall -Wextra -DNDEBUG"

REM Include paths
set "INCLUDES=-I%PROJECT_ROOT%"

REM Source files
set "SOURCES=%PROJECT_ROOT%\RawRamXD_Phase9_RealWorldIntegration.cpp"
set "TEST_SOURCES=%PROJECT_ROOT%\RawRamXD_Phase9_RealWorldTest.cpp"

REM Output files
set "OUTPUT_LIB=%BUILD_DIR%\libRawRamXD_Phase9.a"
set "OUTPUT_TEST=%BUILD_DIR%\Phase9_Test.exe"

REM =============================================================================
REM Build Library (Object File)
REM =============================================================================
echo [1/3] Compiling Phase 9 Library...
g++ %COMMON_FLAGS% %INCLUDES% -c -o "%BUILD_DIR%\Phase9.o" %SOURCES%
if errorlevel 1 (
    echo ERROR: Library compilation failed
    exit /b 1
)
echo   - Phase9.o created
echo.

REM =============================================================================
REM Build Static Library
REM =============================================================================
echo [2/3] Creating Static Library...
ar rcs "%OUTPUT_LIB%" "%BUILD_DIR%\Phase9.o"
if errorlevel 1 (
    echo ERROR: Static library creation failed
    exit /b 1
)
echo   - libRawRamXD_Phase9.a created
echo.

REM =============================================================================
REM Build Test Executable
REM =============================================================================
echo [3/3] Compiling Test Executable...
g++ %COMMON_FLAGS% %INCLUDES% -o "%OUTPUT_TEST%" %TEST_SOURCES% "%BUILD_DIR%\Phase9.o" -lpthread
if errorlevel 1 (
    echo ERROR: Test executable compilation failed
    exit /b 1
)
echo   - Phase9_Test.exe created
echo.

REM =============================================================================
REM Summary
REM =============================================================================
echo =================================================================
echo Build Complete
echo =================================================================
echo Output files:
echo   - %OUTPUT_LIB%
echo   - %OUTPUT_TEST%
echo.
echo To run tests:
echo   cd /d %BUILD_DIR%
echo   Phase9_Test.exe
echo.
echo To run individual gates:
echo   Phase9_Test.exe --j1  (LLM Integration)
echo   Phase9_Test.exe --j2  (Multi-Model Execution)
echo   Phase9_Test.exe --j3  (Dataset Validation)
echo   Phase9_Test.exe --j4  (Benchmarking)
echo   Phase9_Test.exe --j5  (Latency Profiling)
echo   Phase9_Test.exe --full (Full Integration)
echo   Phase9_Test.exe --capi (C API Test)
echo =================================================================

endlocal