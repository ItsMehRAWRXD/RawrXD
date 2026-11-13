@echo off
setlocal
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set RAWRXD_GREEDY=1
set WEIGHT_BUDGET_MIB=2048
set DEEP2_WEIGHT_BUDGET_MIB=2048
cd /d "G:\~dev\rawrxd\build_ninja\bin"
"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\bin_pin\rawr_p1.exe" run "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -p Hello --max-tokens 8 --receipt "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_tiny_host.receipt.json" > "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_tiny_host.out.txt" 2> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_tiny_host.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_tiny_host.exit.txt"
