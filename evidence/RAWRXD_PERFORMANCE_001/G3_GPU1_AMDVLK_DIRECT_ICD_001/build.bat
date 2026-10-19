@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools
cl /nologo /EHsc /std:c++17 /O2 /MD /I"%VULKAN_SDK%\Include" /Fo"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001\obj\\" /Fe"G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001\g3_amdvlk_direct_icd.exe" g3_amdvlk_direct_icd.cpp g3_amdvlk_direct_icd_a0.cpp /link
echo CL_EXIT=%ERRORLEVEL%