@echo off
setlocal
set RAWRXD_NO_OLLAMA=1
set RAWRXD_HOST_DECODE=1
set DEEP2_MINIMAL_ENHANCE=1
set DEEP2_WIDE_DOT_BATCH=1
set DEEP2_SUBMIT_TRACE=1
set DEEP2_ATTN_PARITY_DUMP=
set DEEP2_RUNTIME_GPU_ATTN=
"F:\rawrxd\build_reap\bin\deep2_bench_tps.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --tokens "1 32" --decode 32 --runs 1 > "G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001\ab_A_shared_softmax.log" 2>&1
echo ARM_A_EXIT=%ERRORLEVEL%
exit /b %ERRORLEVEL%
