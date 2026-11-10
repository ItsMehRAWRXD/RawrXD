@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
if errorlevel 1 exit /b 1

set VULKAN_SDK=C:\VulkanSDK\1.4.357.0

cmake --build build-vulkan --config Release --target deep2_fused_lmhead_verify --parallel 4
if errorlevel 1 exit /b 1

echo deep2_fused_lmhead_verify rebuild completed successfully