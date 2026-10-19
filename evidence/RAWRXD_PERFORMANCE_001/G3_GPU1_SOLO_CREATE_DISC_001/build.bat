@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools
cl /nologo /EHsc /std:c++17 /O2 /MD /I"%VULKAN_SDK%\Include" /I. /Fo"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_SOLO_CREATE_DISC_001\obj\\" /Fe"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_SOLO_CREATE_DISC_001\g3_gpu1_solo_create_disc.exe" g3_gpu1_solo_create_disc.cpp g3_gpu1_solo_create_body.cpp dual_vk_7800_ladder_rungs.cpp dual_vk_probe_emit.cpp /link /LIBPATH:"%VULKAN_SDK%\Lib" vulkan-1.lib
echo CL_EXIT=%ERRORLEVEL%