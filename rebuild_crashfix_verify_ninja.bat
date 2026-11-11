@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
if errorlevel 1 exit /b 1

set VULKAN_SDK=C:\VulkanSDK\1.4.357.0

cmake --build build_crashfix_verify --config Release --target RawrXD-Win32IDE-Native --parallel 4
if errorlevel 1 exit /b 1

echo build_crashfix_verify rebuild completed successfully