@echo off
REM ============================================================================
REM Build Pattern Suite - GCC/MinGW Build
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════════════════════════╗
echo ║     RawrXD Pattern Suite Build Script (GCC/MinGW)                      ║
echo ║     Comprehensive Pattern Generator + Debugger Integration           ║
echo ╚══════════════════════════════════════════════════════════════════════╝
echo.

set "SOURCE_DIR=d:\RawrXD\src\reverse"
set "BUILD_DIR=d:\RawrXD\build\pattern_suite"
set "CONFIG_DIR=d:\RawrXD\configs"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Set compiler flags
set "CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -I"d:\RawrXD\include" -I"d:\RawrXD\third_party" -I"d:\RawrXD\third_party\json\include""
set "LDFLAGS=-o %BUILD_DIR%\PatternGeneratorTest.exe"

echo [1/4] Checking source files...
set "FILES_EXIST=1"
if not exist "%SOURCE_DIR%\ComprehensivePatternGenerator.hpp" (
    echo   ERROR: ComprehensivePatternGenerator.hpp not found
    set "FILES_EXIST=0"
)
if not exist "%SOURCE_DIR%\ComprehensivePatternGenerator.cpp" (
    echo   ERROR: ComprehensivePatternGenerator.cpp not found
    set "FILES_EXIST=0"
)
if not exist "%SOURCE_DIR%\PatternGeneratorTest.cpp" (
    echo   ERROR: PatternGeneratorTest.cpp not found
    set "FILES_EXIST=0"
)
if not exist "%SOURCE_DIR%\DebuggerPatternIntegration.hpp" (
    echo   ERROR: DebuggerPatternIntegration.hpp not found
    set "FILES_EXIST=0"
)
if not exist "%SOURCE_DIR%\DebuggerPatternIntegration.cpp" (
    echo   ERROR: DebuggerPatternIntegration.cpp not found
    set "FILES_EXIST=0"
)

if "%FILES_EXIST%"=="0" (
    echo.
    echo Build failed: Missing source files
    exit /b 1
)
echo   All source files found.

echo.
echo [2/4] Compiling Pattern Generator...
g++.exe %CXXFLAGS% -c -o "%BUILD_DIR%\ComprehensivePatternGenerator.o" "%SOURCE_DIR%\ComprehensivePatternGenerator.cpp" 2>&1
if %ERRORLEVEL% neq 0 (
    echo   ERROR: Compilation failed for ComprehensivePatternGenerator.cpp
    exit /b 1
)
echo   ComprehensivePatternGenerator.cpp compiled successfully.

echo.
echo [3/4] Compiling Debugger Integration...
g++.exe %CXXFLAGS% -c -o "%BUILD_DIR%\DebuggerPatternIntegration.o" "%SOURCE_DIR%\DebuggerPatternIntegration.cpp" 2>&1
if %ERRORLEVEL% neq 0 (
    echo   ERROR: Compilation failed for DebuggerPatternIntegration.cpp
    exit /b 1
)
echo   DebuggerPatternIntegration.cpp compiled successfully.

echo.
echo [4/4] Linking test executable...
g++.exe %CXXFLAGS% "%SOURCE_DIR%\PatternGeneratorTest.cpp" "%BUILD_DIR%\ComprehensivePatternGenerator.o" "%BUILD_DIR%\DebuggerPatternIntegration.o" %LDFLAGS% 2>&1
if %ERRORLEVEL% neq 0 (
    echo   ERROR: Linking failed
    exit /b 1
)
echo   PatternGeneratorTest.exe linked successfully.

echo.
echo ╔══════════════════════════════════════════════════════════════════════╗
echo ║     Build Complete!                                                    ║
echo ╚══════════════════════════════════════════════════════════════════════╝
echo.
echo Output files:
echo   - %BUILD_DIR%\PatternGeneratorTest.exe
echo   - %BUILD_DIR%\ComprehensivePatternGenerator.o
echo   - %BUILD_DIR%\DebuggerPatternIntegration.o
echo.
echo To run tests:
echo   %BUILD_DIR%\PatternGeneratorTest.exe
echo.

endlocal
