@echo off
REM Run from a fresh interactive cmd AFTER killing hung ninja/cl/powershell.
setlocal EnableExtensions
set EVID=G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001
set LOG=%EVID%\p0_authoritative.log
echo AUTH_START %DATE% %TIME%> "%LOG%"
taskkill /F /IM ninja.exe >nul 2>&1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM link.exe >nul 2>&1
taskkill /F /IM glslc.exe >nul 2>&1
taskkill /F /IM deep2_bench_tps.exe >nul 2>&1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >> "%LOG%" 2>&1
cd /d F:\rawrxd\build_reap
if exist CMakeFiles\deep2_bench_tps.dir\src\deep2\runtime_graph_executor.cpp.obj del /f CMakeFiles\deep2_bench_tps.dir\src\deep2\runtime_graph_executor.cpp.obj
echo NINJA>> "%LOG%"
ninja -v deep2_bench_tps >> "%LOG%" 2>&1 || (echo NINJA_FAIL>> "%LOG%" & exit /b 2)
echo HASH>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%EVID%\_gpu_attn_p0_hash.ps1" >> "%LOG%" 2>&1
echo ARM_A>> "%LOG%"
set RAWRXD_NO_OLLAMA=1
set RAWRXD_HOST_DECODE=1
set DEEP2_MINIMAL_ENHANCE=1
set DEEP2_WIDE_DOT_BATCH=1
set DEEP2_SUBMIT_TRACE=1
set DEEP2_ATTN_PARITY_DUMP=
set DEEP2_RUNTIME_GPU_ATTN=
"F:\rawrxd\build_reap\bin\deep2_bench_tps.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --tokens "1 32" --decode 32 --runs 1 > "%EVID%\ab_A_shared_softmax.log" 2>&1
echo ARM_B>> "%LOG%"
set DEEP2_RUNTIME_GPU_ATTN=1
"F:\rawrxd\build_reap\bin\deep2_bench_tps.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --tokens "1 32" --decode 32 --runs 1 > "%EVID%\ab_B_shared_softmax.log" 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "%EVID%\_gpu_attn_p0_compare.ps1" >> "%LOG%" 2>&1
findstr /C:"TOKEN_PARITY=FAIL" "%EVID%\ISOLATED_AB.txt" >nul && (
  echo PARITY_DUMP_RERUN>> "%LOG%"
  set DEEP2_ATTN_PARITY_DUMP=1
  set ATTN_SCORE_TRACE=1
  "F:\rawrxd\build_reap\bin\deep2_bench_tps.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --tokens "1 32" --decode 32 --runs 1 > "%EVID%\ab_B_parity_dump.log" 2>&1
  findstr /C:"[attn-parity]" "%EVID%\ab_B_parity_dump.log" > "%EVID%\attn_parity_extract.txt"
)
echo AUTH_DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
