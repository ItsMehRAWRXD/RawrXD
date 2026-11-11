@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
if errorlevel 1 exit /b 1

set VULKAN_SDK=C:\VulkanSDK\1.4.357.0

cmake -S . -B build_crashfix_verify -G "Visual Studio 17 2022" -A x64 -DRAWRXD_REQUIRE_QT=OFF -DENABLE_VULKAN=OFF -DUSE_ZLIB_FETCHCONTENT=OFF -DFETCHCONTENT_ZLIB=OFF -DCMAKE_DISABLE_FIND_PACKAGE_Qt6=TRUE -DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=TRUE -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
if errorlevel 1 exit /b 1

cmake --build build_crashfix_verify --config Release --target RawrXD-Win32IDE-Native --parallel 4
if errorlevel 1 exit /b 1

echo build_crashfix_verify rebuild completed successfully