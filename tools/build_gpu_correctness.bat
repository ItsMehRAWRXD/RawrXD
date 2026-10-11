@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
rem SDK Include is deliberately FIRST so the real Vulkan API is used instead of
rem the repo's include/vulkan/vulkan.h stub (opaque handles only).
cl /std:c++20 /EHsc /O2 /W3 /nologo /I C:\VulkanSDK\1.4.357.0\Include /I F:\rawrxd\include /FeF:\rawrxd\tools\gpu_matmul_correctness.exe F:\rawrxd\tools\gpu_matmul_correctness.cpp F:\rawrxd\src\vulkan_compute.cpp /link C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib
