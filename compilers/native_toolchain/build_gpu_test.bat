@echo off
REM Phase 8.3 GPU Backend Build Script

setlocal enabledelayedexpansion

echo ============================================
echo Phase 8.3: GPU Backend Test Build
echo ============================================
echo.

set SRC_DIR=src\gpu
set VULKAN_DIR=%SRC_DIR%\vulkan
set OBJ_DIR=obj\gpu
set BIN_DIR=bin

REM Create directories
if not exist %OBJ_DIR% mkdir %OBJ_DIR%
if not exist %BIN_DIR% mkdir %BIN_DIR%

REM Compiler flags
set CFLAGS=-std=c++17 -O2 -Wall -DGPU_BACKEND_EXPORTS
set INCLUDES=-I %SRC_DIR% -I %VULKAN_DIR%

REM Check for Vulkan SDK
if exist "C:\VulkanSDK" (
    echo Found Vulkan SDK
    for /d %%D in (C:\VulkanSDK\*) do (
        set VULKAN_SDK=%%D
        goto :found_vulkan
    )
)
echo WARNING: Vulkan SDK not found, using stub implementation
set VULKAN_SDK=

:found_vulkan
if defined VULKAN_SDK (
    echo Using Vulkan SDK: %VULKAN_SDK%
    set INCLUDES=%INCLUDES% -I "%VULKAN_SDK%\Include"
    set LIBS=-L "%VULKAN_SDK%\Lib" -lvulkan-1
) else (
    set INCLUDES=%INCLUDES% -DNO_VULKAN
)

echo.
echo Compiling GPU Backend...

REM Compile GPU backend sources (using stub for now)
g++ %CFLAGS% %INCLUDES% -c %SRC_DIR%\gpu_backend.cpp -o %OBJ_DIR%\gpu_backend.obj %LIBS%
if !errorlevel! neq 0 (
    echo Failed to compile gpu_backend.cpp
    exit /b 1
)

g++ %CFLAGS% %INCLUDES% -c %VULKAN_DIR%\vulkan_backend_stub.cpp -o %OBJ_DIR%\vulkan_backend.obj %LIBS%
if !errorlevel! neq 0 (
    echo Failed to compile vulkan_backend_stub.cpp
    exit /b 1
)

echo.
echo Compiling GPU Backend Test...

REM Compile test
g++ %CFLAGS% %INCLUDES% -o %BIN_DIR%\test_gpu_backend.exe test_gpu_backend.cpp %OBJ_DIR%\gpu_backend.obj %OBJ_DIR%\vulkan_backend.obj %LIBS%

if %errorlevel% neq 0 (
    echo.
    echo ============================================
    echo Build FAILED
    echo ============================================
    exit /b 1
)

echo.
echo ============================================
echo Build SUCCESSFUL
echo Output: %BIN_DIR%\test_gpu_backend.exe
echo ============================================
echo.

REM Run the test
echo Running GPU Backend Test...
echo.
%BIN_DIR%\test_gpu_backend.exe

endlocal
