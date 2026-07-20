@echo off
:: Build script for Fix 5B: KV Cache Residency Integration
:: RawrXD IDE - High-Performance Inference
::
:: This builds the test harness for NEVM-integrated KV cache residency
:: management, validating:
::   - Quantized KV tiers (FP16/Q8/Q4/Q2)
::   - Sliding window residency
::   - Head-aware compression
::   - Emergency eviction
::
:: See: docs/architecture/Fix_5A_KV_Cache_Findings.md

setlocal enabledelayedexpansion

echo ============================================================
echo Fix 5B: KV Cache Residency Integration Build
echo ============================================================
echo.

:: Configuration
set SRC_DIR=%~dp0src
set TEST_DIR=%~dp0tests
set BUILD_DIR=%~dp0build
set OUTPUT_DIR=%~dp0bin

:: Compiler settings
set CXX=cl
set CXXFLAGS=/std:c++17 /O2 /EHsc /W4 /I"%SRC_DIR%" /I"%SRC_DIR%\nevm" /D_CRT_SECURE_NO_WARNINGS
set LDFLAGS=/link /OUT:

:: Create output directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo Configuration:
echo   Source: %SRC_DIR%
echo   Tests:  %TEST_DIR%
echo   Build:  %BUILD_DIR%
echo   Output: %OUTPUT_DIR%
echo.

:: Build the residency test
echo Building test_fix5b_kv_residency.exe...
echo ------------------------------------------------------------

%CXX% %CXXFLAGS% ^
    "%TEST_DIR%\test_fix5b_kv_residency.cpp" ^
    "%SRC_DIR%\memory\RawrXD_KVCache_Residency.cpp" ^
    "%SRC_DIR%\memory\RawrXD_KVCache_Layout.cpp" ^
    "%SRC_DIR%\nevm\nevm_residency.cpp" ^
    "%SRC_DIR%\nevm\nevm_precision_controller.cpp" ^
    "%SRC_DIR%\nevm\nevm_mmu.cpp" ^
    /Fe"%OUTPUT_DIR%\test_fix5b_kv_residency.exe" ^
    /Fo"%BUILD_DIR%\" ^
    /link

if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Build failed with code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo.
echo Build successful: %OUTPUT_DIR%\test_fix5b_kv_residency.exe
echo.

:: Run the test if requested
if "%1"=="--run" (
    echo Running test...
    echo ============================================================
    "%OUTPUT_DIR%\test_fix5b_kv_residency.exe" %2 %3
    if %ERRORLEVEL% neq 0 (
        echo.
        echo TEST FAILED
        exit /b %ERRORLEVEL%
    )
)

if "%1"=="--run-quick" (
    echo Running quick test (1024 tokens)...
    echo ============================================================
    "%OUTPUT_DIR%\test_fix5b_kv_residency.exe" 1024 256
    if %ERRORLEVEL% neq 0 (
        echo.
        echo TEST FAILED
        exit /b %ERRORLEVEL%
    )
)

echo.
echo ============================================================
echo Fix 5B Build Complete
echo ============================================================
echo.
echo Usage:
echo   build_fix5b_residency.bat         - Build only
echo   build_fix5b_residency.bat --run   - Build and run full test
echo   build_fix5b_residency.bat --run-quick - Build and run quick test
echo.

endlocal
