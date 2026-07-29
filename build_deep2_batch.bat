@echo off
:: Build script for Deep2 Batch Model Stress-Test Harness
:: This builds the Deep2_Batch_Test target with PageFaultMonitor integration

echo ==========================================
echo Building Deep2 Batch Model Stress-Test
echo ==========================================

:: Ensure build directory exists
if not exist build_fix3 mkdir build_fix3

:: Configure with CMake (Ninja generator for speed)
echo [1/2] Configuring with CMake...
cmake -B build_fix3 -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_DEEP2_BATCH_TEST=ON
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed
    exit /b 1
)

:: Build the batch test
echo [2/2] Building Deep2_Batch_Test...
cmake --build build_fix3 --target Deep2_Batch_Test -j8
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed
    exit /b 1
)

echo.
echo ==========================================
echo Build Complete: Deep2_Batch_Test
echo Output: build_fix3\bin\Deep2_Batch_Test.exe
echo ==========================================
