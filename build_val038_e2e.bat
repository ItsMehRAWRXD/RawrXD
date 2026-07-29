@echo off
:: Build script for VAL-038 E2E Integration Test
:: This builds the SovereignTest_VAL038_E2E target using the beaconism pattern

echo ==========================================
echo Building VAL-038 E2E Integration Test
echo ==========================================

:: Ensure build directory exists
if not exist build_fix3 mkdir build_fix3

:: Configure with CMake (Ninja generator for speed)
echo [1/2] Configuring with CMake...
cmake -B build_fix3 -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SOVEREIGN_VAL038_E2E=ON
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed
    exit /b 1
)

:: Build the E2E test
echo [2/2] Building SovereignTest_VAL038_E2E...
cmake --build build_fix3 --target SovereignTest_VAL038_E2E -j8
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed
    exit /b 1
)

echo.
echo ==========================================
echo Build Complete: SovereignTest_VAL038_E2E
echo Output: build_fix3\bin\SovereignTest_VAL038_E2E.exe
echo ==========================================
