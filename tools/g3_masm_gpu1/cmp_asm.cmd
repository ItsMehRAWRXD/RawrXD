@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools\g3_masm_gpu1
cl /nologo /MT /FAs /Fac_mt_ci.asm /c /IC:\VulkanSDK\1.4.357.0\Include c_mt_ci.cpp
findstr /i "DWORD PTR QWORD PTR vkCreate Instance apiVersion" c_mt_ci.asm
echo ----
dumpbin /imports G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_MASM_SOLO_A0_001\g3_masm_solo_a0.exe | findstr /i "vulkan vkCreate"
dumpbin /imports G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_MASM_SOLO_A0_001\c_mt_ci.exe | findstr /i "vulkan vkCreate"
