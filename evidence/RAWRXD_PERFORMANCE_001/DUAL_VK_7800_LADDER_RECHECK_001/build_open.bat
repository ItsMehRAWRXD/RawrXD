@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools
cl /nologo /EHsc /std:c++17 /O2 /MD /I"%VULKAN_SDK%\Include" /I. /Fo"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DUAL_VK_7800_LADDER_RECHECK_001\obj_open\\" /Fe"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DUAL_VK_7800_LADDER_RECHECK_001\dual_vk_open_probe.exe" dual_vk_open_probe.cpp dual_vk_probe_device.cpp dual_vk_probe_emit.cpp dual_vk_probe_solo.cpp dual_vk_probe_dual.cpp /link /LIBPATH:"%VULKAN_SDK%\Lib" vulkan-1.lib
echo CL_EXIT=%ERRORLEVEL%