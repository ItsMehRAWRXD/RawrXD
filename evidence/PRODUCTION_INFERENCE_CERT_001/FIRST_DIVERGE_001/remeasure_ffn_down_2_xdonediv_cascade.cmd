@echo off
setlocal DisableDelayedExpansion
REM FFN_DOWN_2 xd-one-div SPV cascade remasure on C740. PROMOTE=0
REM Force absolute src/backend SPV (C740 LoadQ4kSpv first disk path). No EXE rebuild.
set RAWRXD_ALLOW_GPU=1
set RAWR_FORCE_GPU=1
set RAWR_NO_CPU_FALLBACK=1
set DEEP2_GPU_DEVICE_CLASS=DISCRETE
set DEEP2_GPU_POLICY=SINGLE
set RAWRXD_FORCE_VULKAN_QUANT_GEMV=1
set RAWRXD_QUANT_HOST_Q8K_PARITY=0
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
set RAWRXD_STAGE_DUMP_MAX_LAYER=22
set SPV_SRC=G:\~dev\rawrxd\src\backend\gemv_q4k.spv
set RAWRXD_Q4K_SPV=%SPV_SRC%
set RAWRXD_STAGE_DUMP_DIR=G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\stage_dump_ffn_down_2_xdonediv_cascade
set EVID=G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001
if exist "%RAWRXD_STAGE_DUMP_DIR%" rmdir /s /q "%RAWRXD_STAGE_DUMP_DIR%"
mkdir "%RAWRXD_STAGE_DUMP_DIR%"
cd /d G:\~dev\rawrxd\build_ninja\bin
copy /y "%SPV_SRC%" gemv_q4k.spv >nul
copy /y "%SPV_SRC%" "%EVID%\pin\gemv_q4k.spv" >nul
copy /y G:\~dev\rawrxd\src\backend\gemv_q6k.spv gemv_q6k.spv >nul
py -3 -c "import hashlib,pathlib; p=pathlib.Path(r'%SPV_SRC%'); h=hashlib.sha256(p.read_bytes()).hexdigest().upper(); pathlib.Path(r'%EVID%\RUNTIME_SPV_SHA_xdonediv.txt').write_text('RUNTIME_SPV_SHA='+h+'\nLEN='+str(p.stat().st_size)+'\nPATH='+str(p)+'\nPIN_4548=4548BCF1EF5C4ED714041D6EFD7C32570A4EEFC431B008A6D6427CCE902FFF86\nNE_4548='+str(h!='4548BCF1EF5C4ED714041D6EFD7C32570A4EEFC431B008A6D6427CCE902FFF86')+'\n', encoding='utf-8'); print(h, p.stat().st_size)"
set EXE=rawr_gpufwd_C7402085.exe
set OUT=%EVID%\remeasure_ffn_down_2_xdonediv_cascade.out.txt
set ERR=%EVID%\remeasure_ffn_down_2_xdonediv_cascade.err.txt
set EXITF=%EVID%\remeasure_ffn_down_2_xdonediv_cascade.exit.txt
"%EXE%" run G:\~dev\rawrxd\models\tinyllama.gguf -p Hello --max-tokens 1 > "%OUT%" 2> "%ERR%"
echo %ERRORLEVEL%> "%EXITF%"
exit /b %ERRORLEVEL%
