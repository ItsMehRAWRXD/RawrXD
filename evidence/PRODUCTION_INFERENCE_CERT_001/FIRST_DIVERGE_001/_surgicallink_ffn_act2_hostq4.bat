@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1
echo === SURGICAL LIB REPLACE quant_host ===
lib /nologo InferenceEngine.lib /REMOVE:CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj
lib /nologo InferenceEngine.lib CMakeFiles\InferenceEngine.dir\src\vulkan_fwd_quant_host.cpp.obj
if errorlevel 1 exit /b 1
echo === DIRECT LINK hostq4 cand (no ninja thrash) ===
link /nologo /OUT:bin\rawr_gpufwd_ffn_act2_hostq4.exe /machine:x64 /DEBUG /INCREMENTAL:NO /subsystem:console @CMakeFiles\rawr_force.rsp
echo LINK_EXIT=%ERRORLEVEL%
if errorlevel 1 exit /b 1
copy /Y bin\rawr_gpufwd_ffn_act2_hostq4.exe "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin\rawr_ffn_act2_hostq4.exe"
certutil -hashfile bin\rawr_gpufwd_ffn_act2_hostq4.exe SHA256
findstr /C:"q4_ffn=" bin\rawr_gpufwd_ffn_act2_hostq4.exe >nul && echo STRING_OK_q4_ffn || echo STRING_MISSING_q4_ffn
exit /b 0
