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
set WEIGHT_BUDGET_MIB=32768
set DEEP2_WEIGHT_BUDGET_MIB=32768
set RAWRXD_REAP_RETAINED=0
cd /d "G:\~dev\rawrxd\build_ninja\bin"
echo START=%DATE% %TIME%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_glm47.meta.txt"
"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\bin_pin\rawr_p1.exe" run "F:\ollamamodels\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf" -p Hello --max-tokens 8 --receipt "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_glm47.receipt.json"  > "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_glm47.out.txt" 2> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_glm47.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_glm47.exit.txt"
echo END=%DATE% %TIME%>> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_glm47.meta.txt"
