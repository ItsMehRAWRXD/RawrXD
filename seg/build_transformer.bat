@echo off
REM ============================================================================
REM Transformer Runtime Build Script
REM ============================================================================

setlocal EnableDelayedExpansion

REM Configuration
set BUILD_DIR=build
set CONFIG=Release
set VULKAN_ENABLED=OFF

REM Parse arguments
:parse_args
if "%~1"=="" goto :done_parsing
if /I "%~1"=="--vulkan" (
    set VULKAN_ENABLED=ON
    shift
    goto :parse_args
)
if /I "%~1"=="--debug" (
    set CONFIG=Debug
    shift
    goto :parse_args
)
if /I "%~1"=="--clean" (
    if exist %BUILD_DIR% rmdir /S /Q %BUILD_DIR%
    echo Cleaned build directory
    exit /b 0
)
if /I "%~1"=="--help" (
    echo Usage: build_transformer.bat [options]
    echo Options:
    echo   --vulkan    Enable Vulkan backend
    echo   --debug     Build debug configuration
    echo   --clean     Clean build directory
    echo   --help      Show this help
    exit /b 0
)
shift
goto :parse_args
:done_parsing

echo ============================================================================
echo Building Transformer Runtime
echo ============================================================================
echo Configuration: %CONFIG%
echo Vulkan: %VULKAN_ENABLED%
echo.

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd %BUILD_DIR%

REM Configure with CMake
echo Configuring...
cmake .. -DCMAKE_BUILD_TYPE=%CONFIG% -DTRANSFORMER_ENABLE_VULKAN=%VULKAN_ENABLED% -DCMAKE_TOOLCHAIN_FILE=../transformer_runtime.cmake
if errorlevel 1 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

REM Build
echo.
echo Building...
cmake --build . --config %CONFIG% --parallel
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ============================================================================
echo Build Successful
echo ============================================================================
echo.
echo Executable: %BUILD_DIR%\%CONFIG%\test_transformer_runtime.exe
echo.
echo Run with: %BUILD_DIR%\%CONFIG%\test_transformer_runtime.exe
echo.

cd ..
endlocal
