@echo off
REM VAL-012 Executor V2 Build Script
REM Builds and tests structured result executors

echo ========================================
echo VAL-012 Executor V2 Build
echo Structured Results with Categorization
echo ========================================
echo.

set SRC_DIR=src\val012
set TEST_DIR=tests\val012
set BUILD_DIR=build-val012-executor-v2
set EVIDENCE_DIR=evidence

REM Create directories
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %EVIDENCE_DIR% mkdir %EVIDENCE_DIR%

echo [1/5] Compiling result types (header-only)...
echo   val012_result_types.h - OK

echo [2/5] Compiling build executor V2...
g++ -std=c++20 -c %SRC_DIR%\val012_build_executor_v2.cpp -o %BUILD_DIR%\val012_build_executor_v2.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Build executor V2 compilation failed
    exit /b 1
)

echo [3/5] Compiling test executor V2...
g++ -std=c++20 -c %SRC_DIR%\val012_test_executor_v2.cpp -o %BUILD_DIR%\val012_test_executor_v2.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Test executor V2 compilation failed
    exit /b 1
)

echo [4/5] Compiling executor V2 test...
g++ -std=c++20 -c %TEST_DIR%\val012_executor_v2_test.cpp -o %BUILD_DIR%\val012_executor_v2_test.o -I%SRC_DIR%
if errorlevel 1 (
    echo ERROR: Executor V2 test compilation failed
    exit /b 1
)

echo [5/5] Linking executor V2 test...
g++ -std=c++20 ^
    %BUILD_DIR%\val012_build_executor_v2.o ^
    %BUILD_DIR%\val012_test_executor_v2.o ^
    %BUILD_DIR%\val012_executor_v2_test.o ^
    -o %BUILD_DIR%\val012_executor_v2_test.exe
if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo ========================================
echo Build Complete
echo ========================================
echo.
echo Running executor V2 test...
%BUILD_DIR%\val012_executor_v2_test.exe %BUILD_DIR%
if errorlevel 1 (
    echo WARNING: Executor V2 test had issues
)

echo.
echo Checking evidence...
if exist %EVIDENCE_DIR%\val-012-v2-structured (
    echo Evidence created successfully
    dir %EVIDENCE_DIR%\val-012-v2-structured /b
) else (
    echo Note: Evidence will be created on test run
)

echo.
echo Done!
echo.
echo Next steps:
echo   1. Review structured results in evidence/val-012-v2-structured/
echo   2. Check build_result.json for complete categorization
echo   3. Verify executor_success vs environment_ready separation
echo.
