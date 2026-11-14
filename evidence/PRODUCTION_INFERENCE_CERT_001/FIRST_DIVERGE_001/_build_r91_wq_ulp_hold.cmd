@echo off
REM R91: FA006 + WQ AVX dualpipe BE085 + ATTN_OUT ULP hold. PROMOTE=0
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001 || exit /b 1
py -3 _mk_r89_wq_clean_engine.py || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1
set INC=/IG:\~dev\rawrxd\include /IC:\VulkanSDK\1.4.357.0\Include /IG:\~dev\rawrxd\src /IG:\~dev\rawrxd\src\deep2 /IG:\~dev\rawrxd\src\inference /IG:\~dev\rawrxd\src\engine /IG:\~dev\rawrxd\src\core /IG:\~dev\rawrxd\src\codec /IG:\~dev\rawrxd\src\masm /IG:\~dev\rawrxd\src\runtime\governance
set DEF=/DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DRAWR_STANDALONE_INFERENCE=1 /DRAWR_ENABLE_VULKAN=1 /DRAWR_HAS_VULKAN=1 /DRAWR_VULKAN_AVAILABLE=1 /DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /DNDEBUG
set ENG=G:\~dev\rawrxd\src\deep2\_Deep2Engine_r89_wq_clean.cpp
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_q4k.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k_fused.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_q4k_fused.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_quant_host.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_pipe.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_quant_pipe.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_compute.cpp.obj G:\~dev\rawrxd\src\vulkan_compute.cpp || exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj %ENG% || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k_fused.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_pipe.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_compute.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo InferenceEngine.lib CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q4k_fused.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_pipe.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_compute.cpp.obj CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj || exit /b 1
link /nologo /OUT:bin\rawr_attn_pre_o_1_pos1_fa006_r91ulp.exe /machine:x64 /DEBUG /INCREMENTAL:NO /subsystem:console CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRuntime_Open.cpp.obj CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRunDecode.cpp.obj CMakeFiles\rawr.dir\src\reap\ReapPhysicalReduceCalib.cpp.obj @CMakeFiles\rawr_force.rsp
if errorlevel 1 exit /b 1
copy /Y bin\rawr_attn_pre_o_1_pos1_fa006_r91ulp.exe G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin\rawr_attn_pre_o_1_pos1_fa006_r91ulp.exe || exit /b 1
echo PIN_OK
exit /b 0
