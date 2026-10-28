@echo off
setlocal EnableExtensions
set EVID=G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001
set LOG=%EVID%\p0_runner.log
echo ==== P0 START %DATE% %TIME% > "%LOG%"
taskkill /F /IM glslc.exe >nul 2>&1
taskkill /F /IM deep2_bench_tps.exe >nul 2>&1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >> "%LOG%" 2>&1
if errorlevel 1 ( echo VCVARS_FAIL>> "%LOG%" & exit /b 1 )
cd /d F:\rawrxd\build_reap
echo ==== NINJA >> "%LOG%"
ninja deep2_bench_tps >> "%LOG%" 2>&1
if errorlevel 1 ( echo NINJA_FAIL>> "%LOG%" & exit /b 2 )
echo ==== HASH >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%EVID%\_gpu_attn_p0_hash.ps1" >> "%LOG%" 2>&1
echo ==== ARM A >> "%LOG%"
set RAWRXD_NO_OLLAMA=1
set RAWRXD_HOST_DECODE=1
set DEEP2_MINIMAL_ENHANCE=1
set DEEP2_WIDE_DOT_BATCH=1
set DEEP2_SUBMIT_TRACE=1
set DEEP2_ATTN_PARITY_DUMP=
set DEEP2_RUNTIME_GPU_ATTN=
"F:\rawrxd\build_reap\bin\deep2_bench_tps.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --tokens "1 32" --decode 32 --runs 1 > "%EVID%\ab_A_shared_softmax.log" 2>&1
echo ARM_A_EXIT=%ERRORLEVEL% >> "%LOG%"
echo ==== ARM B >> "%LOG%"
set DEEP2_RUNTIME_GPU_ATTN=1
"F:\rawrxd\build_reap\bin\deep2_bench_tps.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --tokens "1 32" --decode 32 --runs 1 > "%EVID%\ab_B_shared_softmax.log" 2>&1
echo ARM_B_EXIT=%ERRORLEVEL% >> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%EVID%\_gpu_attn_p0_compare.ps1" >> "%LOG%" 2>&1
echo ==== P0 DONE %DATE% %TIME% >> "%LOG%"
exit /b 0
