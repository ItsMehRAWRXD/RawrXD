@echo off
REM build_gpu_backend.bat - Build Phase 8.3 GPU Backend

echo ============================================
echo Building GPU Backend (Phase 8.3)
echo ============================================

set SRC_DIR=src\gpu
set OUT_DIR=.
set CXX=g++

REM Compiler flags
set CFLAGS=-O3 -march=native -ffast-math
set CFLAGS=%CFLAGS% -Wall -Wextra
set CFLAGS=%CFLAGS% -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS
set CFLAGS=%CFLAGS% -DGPU_BACKEND_EXPORTS

REM Include paths
set INCLUDES=-I%SRC_DIR% -I%SRC_DIR%\vulkan

REM Check for Vulkan SDK
if not exist "%VULKAN_SDK%\Include\vulkan\vulkan.h" (
    echo WARNING: Vulkan SDK not found at %%VULKAN_SDK%%
    echo Please install Vulkan SDK from https://vulkan.lunarg.com/
    echo.
    echo Attempting to build without Vulkan...
    set VULKAN_LIBS=
) else (
    echo Found Vulkan SDK at %VULKAN_SDK%
    set INCLUDES=%INCLUDES% -I%VULKAN_SDK%\Include
    set VULKAN_LIBS=-L%VULKAN_SDK%\Lib -lvulkan-1
)

echo.
echo Source files:
echo   gpu_backend.cpp
echo   vulkan_backend.cpp
echo   vulkan_memory.cpp
echo   vulkan_kernels.cpp

echo.
echo Building GPU backend DLL...
%CXX% %CFLAGS% %INCLUDES% -shared -o %OUT_DIR%\gpu_backend.dll ^
    %SRC_DIR%\gpu_backend.cpp ^
    %SRC_DIR%\vulkan\vulkan_backend.cpp ^
    %SRC_DIR%\vulkan\vulkan_memory.cpp ^
    %SRC_DIR%\vulkan\vulkan_kernels.cpp ^
    %VULKAN_LIBS% ^
    -Wl,--out-implib,%OUT_DIR%\gpu_backend.lib

if %ERRORLEVEL% neq 0 (
    echo ERROR: GPU backend build failed!
    exit /b 1
)

echo.
echo Building test harness...
%CXX% %CFLAGS% %INCLUDES% -o %OUT_DIR%\gpu_backend_test.exe ^
    %SRC_DIR%\gpu_backend_test.cpp ^
    -L%OUT_DIR% -lgpu_backend

if %ERRORLEVEL% neq 0 (
    echo WARNING: Test harness build failed
) else (
    echo Test harness built successfully
)

echo.
echo ============================================
echo Build complete!
echo ============================================
echo Output files:
dir /b %OUT_DIR%\gpu_backend.dll %OUT_DIR%\gpu_backend.lib 2>nul
dir /b %OUT_DIR%\gpu_backend_test.exe 2>nul
echo.

echo Done!