@echo off
set RAWRXD_GREEDY=1
set RAWRXD_NO_TP=1
set RAWR_SKIP_AUTO_BACKEND=1
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set WEIGHT_BUDGET_MIB=59568
set DEEP2_WEIGHT_BUDGET_MIB=59568
set RAWRXD_REAP_RETAINED=256
set DEEP2_CHAT_TRACE=1
"G:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "F:\ollamamodels\NVIDIA-Nemotron-3-Nano-4B-GGUF\NVIDIA-Nemotron-3-Nano-4B-Q8_0.gguf" -p "Say hi." --max-tokens 8 --receipt "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_nano_host.receipt.json" > "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_nano_host.out.txt" 2> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_nano_host.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\P1_nano_host.exit.txt"
