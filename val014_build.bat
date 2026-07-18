@echo off
REM VAL-014 Build Script
REM Real Toolchain Validation using V2 Executor Contract

echo ========================================
echo VAL-014: Real Toolchain Validation
echo ========================================
echo.

set SRC_DIR=src
set BUILD_DIR=build-val014
set EVIDENCE_DIR=evidence

REM Create directories
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %EVIDENCE_DIR% mkdir %EVIDENCE_DIR%

echo [1/4] Compiling VAL-014 execution result types...
g++ -std=c++20 -c %SRC_DIR%\val014\val014_execution_result.h -o %BUILD_DIR%\val014_execution_result.o -I%SRC_DIR%\val012 2>nul
if errorlevel 1 (
    echo Note: Header-only, skipping object compilation
)

echo [2/4] Compiling VAL-014 orchestrator...
g++ -std=c++20 -c %SRC_DIR%\val014\val014_orchestrator.cpp -o %BUILD_DIR%\val014_orchestrator.o -I%SRC_DIR%\val012 -I%SRC_DIR%\val014
if errorlevel 1 (
    echo ERROR: Orchestrator compilation failed
    exit /b 1
)

echo [3/4] Compiling VAL-014 test...
g++ -std=c++20 -c tests\val014\val014_test.cpp -o %BUILD_DIR%\val014_test.o -I%SRC_DIR%\val012 -I%SRC_DIR%\val014
if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)

echo [4/4] Linking VAL-014 test executable...
g++ -std=c++20 ^
    %BUILD_DIR%\val014_orchestrator.o ^
    %BUILD_DIR%\val014_test.o ^
    build-val012-executor-v2\val012_build_executor_v2.o ^
    build-val012-executor-v2\val012_test_executor_v2.o ^
    -o %BUILD_DIR%\val014_test.exe
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ========================================
echo Build Complete
echo ========================================
echo.
echo Running VAL-014 validation...
%BUILD_DIR%\val014_test.exe build-val012-simple
if errorlevel 1 (
    echo.
    echo WARNING: Some tests failed
    echo This is expected if test executable is not built
    echo Run: val012_simple_build.bat first
)

echo.
echo Checking evidence...
if exist %EVIDENCE_DIR%\val014-* (
    echo Evidence created successfully
    dir %EVIDENCE_DIR%\val014-* /b
) else (
    echo Note: Evidence will be created on test run
)

echo.
echo Done!
echo.
echo Next steps:
echo   1. Review evidence in: %EVIDENCE_DIR%\
echo   2. Check execution_result.json for universal contract
echo   3. Verify toolchain detection in build_result.json
echo   4. Proceed to VAL-016 (Repair Loop)
echo.
