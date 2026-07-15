@echo off
REM ============================================================================
REM build_verify_vulkan_hip.bat — Build and Runtime Verification Script
REM ============================================================================
REM This script builds and runs the minimal working implementations to verify:
REM - Vulkan compute pipeline creation
REM - SPIR-V shader compilation
REM - HIP/ROCm runtime loading
REM - Speculative execution verification loop
REM ============================================================================

echo.
echo =================================================================
echo   RawrXD GPU Backend Build Verification
echo =================================================================
echo.

set VULKAN_SDK=C:\VulkanSDK\1.4.328.1
set VS_PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64

if not exist "%VULKAN_SDK%" (
    echo [ERROR] Vulkan SDK not found at %VULKAN_SDK%
    echo [INFO] Please install Vulkan SDK from https://vulkan.lunarg.com/
    exit /b 1
)

echo [INFO] Vulkan SDK: %VULKAN_SDK%
echo [INFO] VS Tools: %VS_PATH%
echo.

REM Set up environment
call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM ============================================================================
REM Build Vulkan Compute Test
REM ============================================================================
echo [BUILD] Building Vulkan compute test...
echo -----------------------------------------------------------------

cl.exe /EHsc /O2 /W3 /nologo ^
    /I"%VULKAN_SDK%\Include" ^
    "%~dp0src\backend\vulkan_compute_minimal.cpp" ^
    /link /OUT:"%~dp0vulkan_test.exe" ^
    "%VULKAN_SDK%\Lib\vulkan-1.lib" ^
    2>&1 | findstr /V "^Microsoft" | findstr /V "^Copyright"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Vulkan build FAILED
    exit /b 1
)

echo [BUILD] Vulkan compute test: SUCCESS
echo.

REM ============================================================================
REM Build HIP Test
REM ============================================================================
echo [BUILD] Building HIP/ROCm test...
echo -----------------------------------------------------------------

cl.exe /EHsc /O2 /W3 /nologo ^
    "%~dp0src\backend\hip_backend_minimal.cpp" ^
    /link /OUT:"%~dp0hip_test.exe" ^
    2>&1 | findstr /V "^Microsoft" | findstr /V "^Copyright"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] HIP build FAILED
    exit /b 1
)

echo [BUILD] HIP/ROCm test: SUCCESS
echo.

REM ============================================================================
REM Build Speculative Execution Test
REM ============================================================================
echo [BUILD] Building speculative execution test...
echo -----------------------------------------------------------------

cl.exe /EHsc /O2 /W3 /nologo ^
    "%~dp0src\speculative\speculative_execution_minimal.cpp" ^
    /link /OUT:"%~dp0speculative_test.exe" ^
    2>&1 | findstr /V "^Microsoft" | findstr /V "^Copyright"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Speculative execution build FAILED
    exit /b 1
)

echo [BUILD] Speculative execution test: SUCCESS
echo.

REM ============================================================================
REM Run Tests
REM ============================================================================
echo =================================================================
echo   Running Runtime Verification Tests
echo =================================================================
echo.

REM Run Vulkan test
echo [TEST] Running Vulkan compute test...
echo -----------------------------------------------------------------
"%~dp0vulkan_test.exe"
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Vulkan test returned non-zero exit code
    set VULKAN_OK=0
) else (
    set VULKAN_OK=1
)
echo.

REM Run HIP test
echo [TEST] Running HIP/ROCm test...
echo -----------------------------------------------------------------
"%~dp0hip_test.exe"
if %ERRORLEVEL% neq 0 (
    echo [WARNING] HIP test returned non-zero exit code (ROCm may not be installed)
    set HIP_OK=0
) else (
    set HIP_OK=1
)
echo.

REM Run Speculative test
echo [TEST] Running speculative execution test...
echo -----------------------------------------------------------------
"%~dp0speculative_test.exe"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Speculative execution test FAILED
    set SPEC_OK=0
) else (
    set SPEC_OK=1
)
echo.

REM ============================================================================
REM Summary
REM ============================================================================
echo =================================================================
echo   VERIFICATION SUMMARY
echo =================================================================
echo.
if %VULKAN_OK%==1 (
    echo   [PASS] Vulkan compute pipeline: WORKING
) else (
    echo   [FAIL] Vulkan compute pipeline: NOT WORKING
)

if %HIP_OK%==1 (
    echo   [PASS] HIP/ROCm runtime: WORKING
) else (
    echo   [INFO] HIP/ROCm runtime: NOT AVAILABLE (optional)
)

if %SPEC_OK%==1 (
    echo   [PASS] Speculative execution: WORKING
) else (
    echo   [FAIL] Speculative execution: NOT WORKING
)

echo.
echo =================================================================
echo   Build artifacts:
echo     - vulkan_test.exe (Vulkan compute verification)
echo     - hip_test.exe (HIP/ROCm verification)
echo     - speculative_test.exe (Speculative execution verification)
echo =================================================================
echo.

if %VULKAN_OK%==1 if %SPEC_OK%==1 (
    echo [RESULT] Core functionality VERIFIED
    exit /b 0
) else (
    echo [RESULT] Some tests FAILED - see output above
    exit /b 1
)
