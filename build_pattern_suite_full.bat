@echo off
REM ============================================================================
REM Build Pattern Suite - Full Build with VS2022 Environment
REM ============================================================================

call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to initialize VS2022 environment
    exit /b 1
)

setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════════════════════════╗
echo ║     RawrXD Pattern Suite Build Script                                  ║
echo ║     Comprehensive Pattern Generator + Debugger Integration           ║
echo ╚══════════════════════════════════════════════════════════════════════╝
echo.

set "SOURCE_DIR=d:\RawrXD\src\reverse"
set "BUILD_DIR=d:\RawrXD\build\pattern_suite"
set "CONFIG_DIR=d:\RawrXD\configs"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Set compiler flags
set "CXXFLAGS=/std:c++17 /O2 /EHsc /W4 /I"d:\RawrXD\include" /I"d:\RawrXD\third_party" /I"d:\RawrXD\third_party\json\include""
set "LDFLAGS=/link /OUT:%BUILD_DIR%\PatternGeneratorTest.exe"

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
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\ComprehensivePatternGenerator.obj" "%SOURCE_DIR%\ComprehensivePatternGenerator.cpp" 2>&1
if %ERRORLEVEL% neq 0 (
    echo   ERROR: Compilation failed for ComprehensivePatternGenerator.cpp
    exit /b 1
)
echo   ComprehensivePatternGenerator.cpp compiled successfully.

echo.
echo [3/4] Compiling Debugger Integration...
cl.exe %CXXFLAGS% /c /Fo"%BUILD_DIR%\DebuggerPatternIntegration.obj" "%SOURCE_DIR%\DebuggerPatternIntegration.cpp" 2>&1
if %ERRORLEVEL% neq 0 (
    echo   ERROR: Compilation failed for DebuggerPatternIntegration.cpp
    exit /b 1
)
echo   DebuggerPatternIntegration.cpp compiled successfully.

echo.
echo [4/4] Linking test executable...
cl.exe %CXXFLAGS% "%SOURCE_DIR%\PatternGeneratorTest.cpp" "%BUILD_DIR%\ComprehensivePatternGenerator.obj" "%BUILD_DIR%\DebuggerPatternIntegration.obj" %LDFLAGS% 2>&1
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
echo   - %BUILD_DIR%\ComprehensivePatternGenerator.obj
echo   - %BUILD_DIR%\DebuggerPatternIntegration.obj
echo.
echo To run tests:
echo   %BUILD_DIR%\PatternGeneratorTest.exe
echo.

endlocal
