@echo off
REM R103: rebuild rawr with MoE GATE/UP/DOWN/IN STAGE_DIGEST dumps. PROMOTE=0
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1
findstr /c:"MOE_IN_L" G:\~dev\rawrxd\src\deep2\Deep2Engine.cpp >nul || (echo SOURCE_MISSING_MOE_IN & exit /b 9)
set INC=/IG:\~dev\rawrxd\include /IC:\VulkanSDK\1.4.357.0\Include /IG:\~dev\rawrxd\src /IG:\~dev\rawrxd\src\deep2 /IG:\~dev\rawrxd\src\inference /IG:\~dev\rawrxd\src\engine /IG:\~dev\rawrxd\src\core /IG:\~dev\rawrxd\src\codec /IG:\~dev\rawrxd\src\masm /IG:\~dev\rawrxd\src\runtime\governance
set DEF=/DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /DRAWR_STANDALONE_INFERENCE=1 /DRAWR_ENABLE_VULKAN=1 /DRAWR_HAS_VULKAN=1 /DRAWR_VULKAN_AVAILABLE=1 /DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /DNDEBUG
cl /nologo /TP /c /EHsc /std:c++latest /MT /O2 /arch:AVX512 /GS- /W0 %DEF% %INC% /FoCMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj G:\~dev\rawrxd\src\deep2\Deep2Engine.cpp || exit /b 1
lib /nologo /REMOVE:CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj InferenceEngine.lib || exit /b 1
lib /nologo InferenceEngine.lib CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj || exit /b 1
if exist bin\rawr.exe move /Y bin\rawr.exe bin\rawr.exe.pre_r103_moe >nul 2>&1
link /nologo /OUT:bin\rawr_ornith_moe_r103.exe /machine:x64 /DEBUG /INCREMENTAL:NO /subsystem:console CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRuntime_Open.cpp.obj CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRunDecode.cpp.obj CMakeFiles\rawr.dir\src\reap\ReapPhysicalReduceCalib.cpp.obj @CMakeFiles\rawr_force.rsp
if errorlevel 1 exit /b 1
copy /Y bin\rawr_ornith_moe_r103.exe G:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001\bin_pin\probe_rawr.exe.r103_moe.exe || exit /b 1
echo PIN_OK
exit /b 0
