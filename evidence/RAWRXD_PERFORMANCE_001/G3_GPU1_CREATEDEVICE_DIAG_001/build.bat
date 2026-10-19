@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools
cl /nologo /EHsc /std:c++17 /O2 /MD /I"%VULKAN_SDK%\Include" /I. /Fo"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_CREATEDEVICE_DIAG_001\obj\\" /Fe"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_CREATEDEVICE_DIAG_001\g3_gpu1_createdevice_diag.exe" g3_gpu1_createdevice_diag.cpp g3_gpu1_diag_caps.cpp g3_gpu1_diag_ladder.cpp dual_vk_probe_emit.cpp /link /LIBPATH:"%VULKAN_SDK%\Lib" vulkan-1.lib
echo CL_EXIT=%ERRORLEVEL%