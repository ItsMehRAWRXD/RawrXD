@echo off
REM VAL-012 Simple Build Script
REM Compiles directly with g++ without CMake

echo ========================================
echo VAL-012: Simple Build (g++ direct)
echo ========================================
echo.

set SRC_DIR=src\val012
set TEST_DIR=tests\val012
set BUILD_DIR=build-val012-simple
set EVIDENCE_DIR=evidence

REM Create directories
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %EVIDENCE_DIR% mkdir %EVIDENCE_DIR%

echo [1/3] Compiling controller...
g++ -std=c++20 -c %SRC_DIR%\val012_controller.cpp -o %BUILD_DIR%\val012_controller.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Controller compilation failed
    exit /b 1
)

echo [2/3] Compiling test...
g++ -std=c++20 -c %TEST_DIR%\val012_test.cpp -o %BUILD_DIR%\val012_test.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Test compilation failed
    exit /b 1
)

echo [3/3] Linking...
g++ -std=c++20 %BUILD_DIR%\val012_controller.o %BUILD_DIR%\val012_test.o -o %BUILD_DIR%\val012_test.exe
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ========================================
echo Build Complete
echo ========================================
echo.
echo Running test...
%BUILD_DIR%\val012_test.exe
if errorlevel 1 (
    echo ERROR: Test failed
    exit /b 1
)

echo.
echo Checking evidence...
if exist %EVIDENCE_DIR%\val-012-test-* (
    echo Evidence created successfully
    dir %EVIDENCE_DIR%\val-012-test-* /b
) else (
    echo WARNING: No evidence found
)

echo.
echo Done!
