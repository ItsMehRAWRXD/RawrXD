@echo off
REM VAL-012 Build Script
REM Builds the autonomous loop closure vertical slice

echo ========================================
echo VAL-012: Autonomous Loop Closure Build
echo ========================================
echo.

set BUILD_DIR=build-val012
set EVIDENCE_DIR=evidence

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Create evidence directory
if not exist %EVIDENCE_DIR% mkdir %EVIDENCE_DIR%

cd %BUILD_DIR%

echo [1/5] Configuring CMake...
cmake ..
if errorlevel 1 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

echo [2/5] Building VAL-012 Controller...
cmake --build . --target val012_controller --config Release
if errorlevel 1 (
    echo ERROR: Build failed for val012_controller
    exit /b 1
)

echo [3/5] Building VAL-012 Test...
cmake --build . --target val012_test --config Release
if errorlevel 1 (
    echo ERROR: Build failed for val012_test
    exit /b 1
)

echo [4/5] Running VAL-012 Test...
.\Release\val012_test.exe
if errorlevel 1 (
    echo ERROR: VAL-012 test failed
    exit /b 1
)

echo [5/5] Checking evidence...
if exist ..\%EVIDENCE_DIR%\val-012-test-* (
    echo Evidence directory created successfully
    dir ..\%EVIDENCE_DIR%\val-012-test-* /b
) else (
    echo WARNING: No evidence directory found
)

cd ..

echo.
echo ========================================
echo VAL-012 Build Complete
echo ========================================
echo.
echo Next steps:
echo   1. Check evidence in: %EVIDENCE_DIR%\
echo   2. Verify completion.json
echo   3. Review events.json
echo.
