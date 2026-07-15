@echo off
setlocal enabledelayedexpansion

echo ============================================
echo Building GPU Backend Validation Test
echo ============================================
echo.

set VULKAN_SDK=C:\VulkanSDK\1.4.328.1
set SRC_DIR=%~dp0\src\gpu
set OUT_DIR=%~dp0

set INCLUDES=-I%VULKAN_SDK%\Include -I%~dp0\src
set LIBS=%VULKAN_SDK%\Lib\vulkan-1.lib

set SOURCES=%SRC_DIR%\gpu_backend.cpp ^
    %SRC_DIR%\vulkan\vulkan_backend.cpp ^
    %SRC_DIR%\vulkan\vulkan_memory.cpp ^
    %SRC_DIR%\vulkan\vulkan_kernels.cpp ^
    %SRC_DIR%\cpu_reference_kernels.cpp ^
    %SRC_DIR%\gpu_validation_test.cpp

echo Compiling GPU validation test...
echo.

g++ -O3 -std=c++17 %INCLUDES% %SOURCES% %LIBS% -o %OUT_DIR%\gpu_validation_test.exe 2>&1

if errorlevel 1 (
    echo.
    echo ============================================
    echo BUILD FAILED
    echo ============================================
    exit /b 1
) else (
    echo.
    echo ============================================
    echo BUILD SUCCESSFUL
    echo ============================================
    echo.
    echo Running validation test...
    echo.
    %OUT_DIR%\gpu_validation_test.exe
    exit /b 0
)
