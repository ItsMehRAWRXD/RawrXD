@echo off
REM Build and Test Script for RawrXD Backend Selector
REM Compiles backend selector, runs tests, validates GPU detection

setlocal EnableDelayedExpansion

echo ========================================
echo RawrXD Backend Selector - Build ^& Test
echo ========================================
echo.

set "SRC_DIR=%~dp0"
set "BUILD_DIR=%SRC_DIR%\build"
set "VS_TOOLS=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"

REM Check for VS2022 tools
if not exist "%VS_TOOLS%\cl.exe" (
    echo ERROR: VS2022 tools not found at %VS_TOOLS%
    echo Please update VS_TOOLS path
    exit /b 1
)

set "PATH=%VS_TOOLS%;%PATH%"

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/5] Checking Vulkan SDK...
set "VULKAN_SDK=C:\VulkanSDK\1.3.275.0"
if not exist "%VULKAN_SDK%" (
    echo WARNING: Vulkan SDK not found at %VULKAN_SDK%
    echo GPU detection may fail
    set "VULKAN_LIB="
) else (
    echo Found: %VULKAN_SDK%
    set "VULKAN_LIB=/I"%VULKAN_SDK%\Include" /link "%VULKAN_SDK%\Lib\vulkan-1.lib""
)

echo.
echo [2/5] Compiling backend selector...
cl.exe /std:c++17 /EHsc /O2 /W3 /nologo ^
    /I"%SRC_DIR%\.." ^
    /I"%SRC_DIR%" ^
    /D_HAS_EXCEPTIONS=0 ^
    %VULKAN_LIB% ^
    /Fe"%BUILD_DIR%\test_backend.exe" ^
    "%SRC_DIR%\test_backend_real.cpp" ^
    "%SRC_DIR%\backend_selector_real.cpp" ^
    "%SRC_DIR%\model_caller_integration.cpp" ^
    "%SRC_DIR%\vulkan_kernels_real.cpp"

if errorlevel 1 (
    echo FAILED: Compilation error
    exit /b 1
)
echo OK: test_backend.exe

echo.
echo [3/5] Running backend tests...
echo ----------------------------------------
"%BUILD_DIR%\test_backend.exe"
set TEST_RESULT=%ERRORLEVEL%
echo ----------------------------------------

if %TEST_RESULT% neq 0 (
    echo FAILED: Tests returned %TEST_RESULT%
    exit /b 1
)
echo OK: All tests passed

echo.
echo [4/5] Checking environment variables...
echo Current settings:
echo   RAWRXD_BACKEND=%RAWRXD_BACKEND%
echo   RAWRXD_MEDUSA_HEADS=%RAWRXD_MEDUSA_HEADS%
echo   RAWRXD_CONTEXT=%RAWRXD_CONTEXT%
echo   RAWRXD_VRAM_BUDGET=%RAWRXD_VRAM_BUDGET%

echo.
echo [5/5] Build summary:
echo   Output: %BUILD_DIR%\test_backend.exe

if exist "%BUILD_DIR%\test_backend.exe" (
    echo   Size: %~zBUILD_DIR%\test_backend.exe bytes
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL
    echo ========================================
    echo.
    echo Next steps:
    echo   1. Compile shaders: cd shaders ^&^& build_shaders.bat
    echo   2. Test with GPU:   set RAWRXD_BACKEND=medusa ^&^& test_backend.exe
    echo   3. Run benchmark:  test_backend.exe --benchmark
    echo.
    exit /b 0
) else (
    echo   ERROR: Output file not created
    exit /b 1
)
