@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv G:\~dev\rawrxd\src\backend\gemv_q4k.spv >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv bin\gemv_q4k.spv >nul
link /nologo /OUT:bin\rawr_attn_pre_o_0_pos1_fa40e_r85b.exe /machine:x64 /DEBUG /INCREMENTAL:NO /subsystem:console CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRuntime_Open.cpp.obj CMakeFiles\rawr.dir\src\deep2\lavapath\ProductRunDecode.cpp.obj CMakeFiles\rawr.dir\src\reap\ReapPhysicalReduceCalib.cpp.obj @CMakeFiles\rawr_force.rsp
if errorlevel 1 exit /b 1
copy /Y bin\rawr_attn_pre_o_0_pos1_fa40e_r85b.exe G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin\rawr_attn_pre_o_0_pos1_fa40e_r85b.exe || exit /b 1
certutil -hashfile bin\tip_land_6754616E.exe SHA256 | findstr /i "6754616E" >nul || (echo TIP_DRIFT & exit /b 8)
certutil -hashfile bin\rawr_gpufwd_C7402085.exe SHA256 | findstr /i "C7402085" >nul || (echo C740_DRIFT & exit /b 8)
findstr /c:"ATTN_GGML_FA_F16" bin\rawr_attn_pre_o_0_pos1_fa40e_r85b.exe >nul || (echo PIN_MISSING_FA & exit /b 7)
certutil -hashfile bin\rawr_attn_pre_o_0_pos1_fa40e_r85b.exe SHA256
echo PIN_OK
exit /b 0
