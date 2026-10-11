@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set VK_INC=C:\VulkanSDK\1.4.357.0\Include
cl /std:c++20 /EHsc /O2 /W3 /nologo ^
  /DRAWXRD_VULKAN_SDK_HEADER="\"%VK_INC%/vulkan/vulkan.h\"" ^
  /I %VK_INC% ^
  /I F:\rawrxd\include ^
  /FeF:\rawrxd\tools\gpu_rope_verify.exe ^
  F:\rawrxd\tools\gpu_rope_verify.cpp ^
  F:\rawrxd\src\vulkan_compute.cpp ^
  /link C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib
