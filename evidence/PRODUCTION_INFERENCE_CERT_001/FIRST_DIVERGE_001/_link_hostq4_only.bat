@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1
if exist CMakeFiles\cmake.check_cache ren CMakeFiles\cmake.check_cache cmake.check_cache.bak_hq4b
set INC=/IG:\~dev\rawrxd\include /IC:\VulkanSDK\1.4.357.0\Include /IG:\~dev\rawrxd\src /IG:\~dev\rawrxd\src\deep2 /IG:\~dev\rawrxd\src\inference /IG:\~dev\rawrxd\src\engine /IG:\~dev\rawrxd\src\core /IG:\~dev\rawrxd\src\codec /IG:\~dev\rawrxd\src\masm /IG:\~dev\rawrxd\src\runtime\governance
set DEF=/DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DRAWR_STANDALONE_INFERENCE=1 /DRAWR_ENABLE_VULKAN=1 /DRAWR_HAS_VULKAN=1 /DRAWR_VULKAN_AVAILABLE=1 /DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /DNDEBUG /DHAS_BRUTAL_GZIP_MASM=1
echo COMPILE_QUANT
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_quant_host.cpp
if errorlevel 1 exit /b 1
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q6k_host.cpp.obj G:\~dev\rawrxd\src\vulkan_fwd_q6k_host.cpp
if errorlevel 1 exit /b 1
echo LINK_HOSTQ4
del /f /q bin\rawr_gpufwd_ffn_act2_hostq4.exe 2>nul
link /nologo /OUT:bin\rawr_gpufwd_ffn_act2_hostq4.exe /machine:x64 /DEBUG /INCREMENTAL:NO /subsystem:console CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_q6k_host.cpp.obj @CMakeFiles\rawr_force.rsp
echo LINK_EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b 1
copy /Y bin\rawr_gpufwd_ffn_act2_hostq4.exe G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin\rawr_ffn_act2_hostq4.exe
for %%A in (bin\rawr_gpufwd_ffn_act2_hostq4.exe) do echo CAND_LEN=%%~zA CAND_TIME=%%~tA
exit /b 0
