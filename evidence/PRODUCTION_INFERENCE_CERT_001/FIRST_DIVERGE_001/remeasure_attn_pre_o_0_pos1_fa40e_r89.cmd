@echo off
setlocal DisableDelayedExpansion
REM FA+pairwise F32 RMSNorm + SPV40E remasure. PROMOTE=0 TIP_CLIMB=HOLD
set RAWRXD_ALLOW_GPU=1
set RAWR_FORCE_GPU=1
set RAWR_NO_CPU_FALLBACK=1
set DEEP2_GPU_DEVICE_CLASS=DISCRETE
set DEEP2_GPU_POLICY=SINGLE
set RAWRXD_FORCE_VULKAN_QUANT_GEMV=1
set RAWRXD_QUANT_HOST_Q8K_PARITY=0
set RAWRXD_Q6_HOST_FFN_DOWN=0
set RAWRXD_Q4_HOST_ATTN=0
set RAWRXD_Q4_HOST_FFN_DOWN=0
set RAWRXD_RAW_PROMPT=1
set RAWRXD_ADD_BOS=1
set RAWRXD_PROMPT_TOKEN_IDS=1,15043
set RAWRXD_STAGE_DIGEST=1
set RAWRXD_GREEDY=1
set RAWRXD_LOGIT_TOP10=1
set CLI_GPU_LAW=1
set ALLOW_GPU=1
set FORCE_GPU=1
set NO_CPU_FALLBACK=1
set HOST_DECODE=0
set WEIGHT_BUDGET_MIB=59568
set RAWRXD_GPU_FWD=0
set RAWRXD_KV_FP16_ROUNDTRIP=1
set RAWRXD_STAGE_DUMP_MAX_LAYER=3
set RAWRXD_STAGE_DUMP_DIR=G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\stage_dump_attn_pre_o_0_pos1_fa40e_r89
if exist "%RAWRXD_STAGE_DUMP_DIR%" rmdir /s /q "%RAWRXD_STAGE_DUMP_DIR%"
mkdir "%RAWRXD_STAGE_DUMP_DIR%"
cd /d G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\pin
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv G:\~dev\rawrxd\src\backend\gemv_q4k.spv >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv gemv_q4k.spv >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q4k.spv.xdonediv G:\~dev\rawrxd\build_ninja\bin\gemv_q4k.spv >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q6k.spv gemv_q6k.spv >nul
set EXE=rawr_attn_pre_o_0_pos1_fa40e_r89.exe
set OUT=G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\remeasure_attn_pre_o_0_pos1_fa40e_r89.out.txt
set ERR=G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\remeasure_attn_pre_o_0_pos1_fa40e_r89.err.txt
set EXITF=G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\remeasure_attn_pre_o_0_pos1_fa40e_r89.exit.txt
"%EXE%" run G:\~dev\rawrxd\models\tinyllama.gguf -p Hello --max-tokens 1 > "%OUT%" 2> "%ERR%"
echo %ERRORLEVEL%> "%EXITF%"
exit /b %ERRORLEVEL%
