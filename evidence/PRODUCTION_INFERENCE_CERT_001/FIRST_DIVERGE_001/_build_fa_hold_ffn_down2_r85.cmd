@echo off
REM Fresh FA F16 private pin + keep SPV40E controlling. PROMOTE=0 TIP_CLIMB=HOLD
setlocal DisableDelayedExpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1

findstr /c:"ATTN_GGML_FA_F16=1" G:\~dev\rawrxd\src\deep2\KVCache.cpp >nul || (echo SOURCE_MISSING_FA & exit /b 9)

REM Ensure controlling SPV40E on disk before link/run
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv G:\~dev\rawrxd\src\backend\gemv_q4k.spv >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv gemv_q4k.spv >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv bin\gemv_q4k.spv >nul

set INC=/IG:\~dev\rawrxd\include /IC:\VulkanSDK\1.4.357.0\Include /IG:\~dev\rawrxd\src /IG:\~dev\rawrxd\src\deep2 /IG:\~dev\rawrxd\src\inference /IG:\~dev\rawrxd\src\engine /IG:\~dev\rawrxd\src\core /IG:\~dev\rawrxd\src\codec /IG:\~dev\rawrxd\src\masm /IG:\~dev\rawrxd\src\runtime\governance
set DEF=/DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DRAWR_STANDALONE_INFERENCE=1 /DRAWR_ENABLE_VULKAN=1 /DRAWR_HAS_VULKAN=1 /DRAWR_VULKAN_AVAILABLE=1 /DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /DNDEBUG

REM Fresh compile FA KVCache + Q4K loader (fnv banner) into InferenceEngine.lib
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\deep2\KVCache.cpp.obj G:\~dev\rawrxd\src\deep2\KVCache.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_q4k.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k_host.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_q4k_host.cpp || exit /b 1

lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\deep2\KVCache.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k_host.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo InferenceEngine.lib CMakeFiles\InferenceEngine.dir\src\deep2\KVCache.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k_host.cpp.obj || exit /b 1

link /nologo /OUT:bin\rawr_attn_pre_o_0_pos1_fa40e_r85.exe /machine:x64 /DEBUG /INCREMENTAL:NO /subsystem:console CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRuntime_Open.cpp.obj CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRunDecode.cpp.obj CMakeFiles\rawr.dir\src\reap\ReapPhysicalReduceCalib.cpp.obj @CMakeFiles\rawr_force.rsp
if errorlevel 1 exit /b 1

copy /Y bin\rawr_attn_pre_o_0_pos1_fa40e_r85.exe G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin\rawr_attn_pre_o_0_pos1_fa40e_r85.exe || exit /b 1

REM Verify tip + C740 untouched
certutil -hashfile bin\tip_land_6754616E.exe SHA256 | findstr /i "6754616E" >nul || (echo TIP_DRIFT & exit /b 8)
certutil -hashfile bin\rawr_gpufwd_C7402085.exe SHA256 | findstr /i "C7402085" >nul || (echo C740_DRIFT & exit /b 8)

findstr /c:"ATTN_GGML_FA_F16" bin\rawr_attn_pre_o_0_pos1_fa40e_r85.exe >nul || (echo PIN_MISSING_FA_STRING & exit /b 7)
echo PIN_OK
exit /b 0
