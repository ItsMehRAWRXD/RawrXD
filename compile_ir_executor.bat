@echo off
cd /d F:\rawrxd
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

rem RAWRXD_DEEP2_GPU_DISPATCH_001
rem The Vulkan include dir is deliberately placed first so the real SDK header
rem is used instead of include/vulkan/vulkan.h, which is a stub that declares
rem only opaque handles. RAWRXD_VULKAN_SDK_HEADER makes that stub forward to
rem the real header as well, so the ordering is belt and braces.
set VK_INC=C:\VulkanSDK\1.4.357.0\Include

cl.exe /nologo /std:c++20 /W4 /WX- /EHsc /O2 ^
    /I "%VK_INC%" ^
    /I "F:\rawrxd\src" ^
    /I "F:\rawrxd\include" ^
    /I "F:\rawrxd\src\deep2" ^
    /I "F:\rawrxd\src\modelgenie" ^
    /I "F:\rawrxd\src\deep2\modelgenie" ^
    /I "F:\rawrxd\tools" ^
    /I "F:\rawrxd\generated\DeepSeek-V2-Lite-Chat" ^
    /DRAWXRD_VULKAN_SDK_HEADER="\"%VK_INC%/vulkan/vulkan.h\"" ^
    "F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenome.cpp" ^
    "F:\rawrxd\src\deep2\modelgenie\ModelGenomeReader.cpp" ^
    "F:\rawrxd\src\modelgenie\ModelGenieExecutor.cpp" ^
    "F:\rawrxd\src\vulkan_compute.cpp" ^
    /link "C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib" ^
    /Fe"F:\rawrxd\tmp_build\modelgenie_ir_executor.exe"
