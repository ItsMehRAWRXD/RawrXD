@echo off
cd /d "g:\~dev\rawrxd\build_ninja\bin"
set WEIGHT_BUDGET=
set E8B0M=
set RAWR_REAP_EXPORT_DIR=
set RAWR_REAP_EXPORT_EXPERIMENTAL=
set RAWRXD_DUALSTICK=
set RAWRXD_REAP_RETAINED=
set RAWRXD_HOST_DECODE=0
set R1_HOST_FLOOR=0
set RAWRXD_ALLOW_GPU=1
set DEEP2_WEIGHT_BUDGET_MIB=8192
set WEIGHT_BUDGET_MIB=8192
"g:\~dev\rawrxd\build_ninja\bin\rawr_cert_pin.exe" run "G:\~dev\rawrxd\models\tinyllama.gguf" -p Hello --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_tinyllama_gpu.receipt.json"  > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_tinyllama_gpu.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_tinyllama_gpu.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_tinyllama_gpu.exit.txt"
