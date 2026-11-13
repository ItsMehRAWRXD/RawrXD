@echo off
setlocal
set WEIGHT_BUDGET=
set E8B0M=
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set RAWRXD_GREEDY=1
set RAWRXD_NO_TP=1
set RAWR_SKIP_AUTO_BACKEND=1
set DEEP2_CHAT_TRACE=1
set WEIGHT_BUDGET_MIB=59568
set DEEP2_WEIGHT_BUDGET_MIB=59568
set RAWRXD_REAP_RETAINED=27
echo START=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_mm_full_reap.meta.txt"
"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\bin_pin\rawr_p1.exe" run "F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" -p Hello --max-tokens 8 --receipt "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_mm_full_reap.receipt.json" --reap 16GB/8 > "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_mm_full_reap.out.txt" 2> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_mm_full_reap.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_mm_full_reap.exit.txt"
echo END=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_mm_full_reap.meta.txt"
