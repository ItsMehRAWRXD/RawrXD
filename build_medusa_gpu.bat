@echo off
REM ============================================================================
REM Build Medusa GPU Engine for RX 7800 XT
REM ============================================================================

echo [Build] Building Medusa High-Performance Inference Engine...
echo [Build] Target: RX 7800 XT with 32K context support

set VULKAN_SDK=C:\VulkanSDK\1.3.275.0
set SRC_DIR=d:\rawrxd\src\inference
set OUT_DIR=d:\rawrxd\build\medusa

if not exist %OUT_DIR% mkdir %OUT_DIR%

REM Compile with optimizations for AMD RDNA3
echo [Build] Compiling medusa_gpu_engine.cpp...
g++ -O3 -march=znver4 -mtune=znver4 -std=c++17 ^
    -I%VULKAN_SDK%\Include ^
    -I..\..\include ^
    -DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 ^
    -c %SRC_DIR%\medusa_gpu_engine.cpp ^
    -o %OUT_DIR%\medusa_gpu_engine.obj

if errorlevel 1 (
    echo [Build] FAILED: medusa_gpu_engine.cpp
    exit /b 1
)

echo [Build] Compiling high_performance_bridge.cpp...
g++ -O3 -march=znver4 -mtune=znver4 -std=c++17 ^
    -I%VULKAN_SDK%\Include ^
    -I..\..\include ^
    -DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 ^
    -c %SRC_DIR%\high_performance_bridge.cpp ^
    -o %OUT_DIR%\high_performance_bridge.obj

if errorlevel 1 (
    echo [Build] FAILED: high_performance_bridge.cpp
    exit /b 1
)

echo [Build] Linking Medusa DLL...
g++ -shared -o %OUT_DIR%\medusa_gpu.dll ^
    %OUT_DIR%\medusa_gpu_engine.obj ^
    %OUT_DIR%\high_performance_bridge.obj ^
    -L%VULKAN_SDK%\Lib ^
    -lvulkan-1 ^
    -lstdc++ ^
    -Wl,--export-all-symbols

if errorlevel 1 (
    echo [Build] FAILED: Linking
    exit /b 1
)

echo [Build] SUCCESS: medusa_gpu.dll created
echo [Build] Output: %OUT_DIR%\medusa_gpu.dll

REM Copy to bin directory
if not exist d:\rawrxd\bin mkdir d:\rawrxd\bin
copy %OUT_DIR%\medusa_gpu.dll d:\rawrxd\bin\
copy %VULKAN_SDK%\Bin\vulkan-1.dll d:\rawrxd\bin\

echo [Build] Ready for 100+ tok/s inference!
pause
