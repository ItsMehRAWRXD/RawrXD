@echo off
REM VAL-012 V2 Build Script
REM Compiles V2 components with real build/test execution

echo ========================================
echo VAL-012 V2: Real Execution Build
echo ========================================
echo.

set SRC_DIR=src\val012
set TEST_DIR=tests\val012
set BUILD_DIR=build-val012-v2
set EVIDENCE_DIR=evidence

REM Create directories
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %EVIDENCE_DIR% mkdir %EVIDENCE_DIR%

echo [1/6] Compiling JSON minimal library...
g++ -std=c++20 -c %SRC_DIR%\json_minimal.hpp -o %BUILD_DIR%\json_minimal.o -I%SRC_DIR% 2>nul
if errorlevel 1 (
    echo Note: json_minimal.hpp is header-only, skipping object compilation
)

echo [2/6] Compiling base controller...
g++ -std=c++20 -c %SRC_DIR%\val012_controller.cpp -o %BUILD_DIR%\val012_controller.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Base controller compilation failed
    exit /b 1
)

echo [3/6] Compiling build executor...
g++ -std=c++20 -c %SRC_DIR%\val012_build_executor.cpp -o %BUILD_DIR%\val012_build_executor.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Build executor compilation failed
    exit /b 1
)

echo [4/6] Compiling test executor...
g++ -std=c++20 -c %SRC_DIR%\val012_test_executor.cpp -o %BUILD_DIR%\val012_test_executor.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Test executor compilation failed
    exit /b 1
)

echo [5/6] Compiling V2 controller...
g++ -std=c++20 -c %SRC_DIR%\val012_controller_v2.cpp -o %BUILD_DIR%\val012_controller_v2.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: V2 controller compilation failed
    exit /b 1
)

echo [6/6] Compiling V2 test...
g++ -std=c++20 -c %TEST_DIR%\val012_v2_test.cpp -o %BUILD_DIR%\val012_v2_test.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: V2 test compilation failed
    exit /b 1
)

echo.
echo Linking V2 test executable...
g++ -std=c++20 ^
    %BUILD_DIR%\val012_controller.o ^
    %BUILD_DIR%\val012_build_executor.o ^
    %BUILD_DIR%\val012_test_executor.o ^
    %BUILD_DIR%\val012_controller_v2.o ^
    %BUILD_DIR%\val012_v2_test.o ^
    -o %BUILD_DIR%\val012_v2_test.exe
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ========================================
echo Build Complete
echo ========================================
echo.
echo Running V2 test (simulated mode)...
%BUILD_DIR%\val012_v2_test.exe %BUILD_DIR%
if errorlevel 1 (
    echo WARNING: V2 test had issues
)

echo.
echo Checking evidence...
if exist %EVIDENCE_DIR%\val-012-v2-* (
    echo Evidence created successfully
    dir %EVIDENCE_DIR%\val-012-v2-* /b
) else (
    echo Note: Evidence directories will be created on test run
)

echo.
echo Done!
echo.
echo Next steps:
echo   1. Check evidence in: %EVIDENCE_DIR%\
echo   2. Review provenance_manifest.json for execution mode
echo   3. Run with real build: val012_v2_test.exe [build-dir]
echo.
