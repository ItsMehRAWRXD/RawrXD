@echo off
setlocal
set RAWRXD_GREEDY=1
set RAWRXD_NO_TP=1
set WEIGHT_BUDGET=E8B0M
set WEIGHT_BUDGET_MIB=59568
set DEEP2_WEIGHT_BUDGET_MIB=59568
set RAWR_SKIP_AUTO_BACKEND=1
set DEEP2_CHAT_TRACE=1
set RAWRXD_RAW_PROMPT=1
set RAWRXD_REAP_RETAINED=27
cd /d "G:\~dev\rawrxd\build_ninja\bin"
echo START=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\mm_phys.meta.txt"
rawr.exe run "F:\ollamamodels\MiniMax-M2.7-REAP16-CALIB\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" -p Hi --max-tokens 8 > "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\mm_phys.combined.txt" 2>&1
echo EXIT=%ERRORLEVEL%>> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\mm_phys.meta.txt"
echo END=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\mm_phys.meta.txt"
