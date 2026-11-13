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
set RAWRXD_REAP_RETAINED=8
echo START=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_kimi_reap.meta.txt"
"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\bin_pin\rawr_p1.exe" run "F:\ollamamodels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf" -p Hello --max-tokens 8 --receipt "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_kimi_reap.receipt.json" --reap 30GB/8 > "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_kimi_reap.out.txt" 2> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_kimi_reap.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_kimi_reap.exit.txt"
echo END=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_kimi_reap.meta.txt"
