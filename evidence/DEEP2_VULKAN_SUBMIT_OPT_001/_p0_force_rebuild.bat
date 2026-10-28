@echo off
setlocal EnableExtensions
set EVID=G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001
set LOG=%EVID%\p0_force_rebuild.log
echo FORCE_REBUILD_START %DATE% %TIME%> "%LOG%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >> "%LOG%" 2>&1
cd /d F:\rawrxd\build_reap
echo TOUCH_OBJ>> "%LOG%"
if exist CMakeFiles\deep2_bench_tps.dir\src\deep2\runtime_graph_executor.cpp.obj del /f CMakeFiles\deep2_bench_tps.dir\src\deep2\runtime_graph_executor.cpp.obj >> "%LOG%" 2>&1
echo NINJA_BEGIN>> "%LOG%"
ninja -v deep2_bench_tps >> "%LOG%" 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>> "%LOG%"
echo HASH_BEGIN>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%EVID%\_gpu_attn_p0_hash.ps1" >> "%LOG%" 2>&1
echo HASH_EXIT=%ERRORLEVEL%>> "%LOG%"
for %%I in (F:\rawrxd\build_reap\bin\deep2_bench_tps.exe) do echo EXE_TIME=%%~tI SIZE=%%~zI>> "%LOG%"
echo FORCE_REBUILD_DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
