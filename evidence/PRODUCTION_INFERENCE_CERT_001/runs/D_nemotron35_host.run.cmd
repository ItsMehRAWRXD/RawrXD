@echo off
cd /d "g:\~dev\rawrxd\build_ninja\bin"
set WEIGHT_BUDGET=
set E8B0M=
set RAWR_REAP_EXPORT_DIR=
set RAWR_REAP_EXPORT_EXPERIMENTAL=
set RAWRXD_DUALSTICK=
set RAWRXD_REAP_RETAINED=
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set DEEP2_WEIGHT_BUDGET_MIB=59568
set WEIGHT_BUDGET_MIB=59568
"g:\~dev\rawrxd\build_ninja\bin\rawr_cert_pin.exe" run "G:\~dev\rawrxd\models\_matrix_f\gguf\nemotron-3.5-lightning-30b-Q4_K_M.gguf" -p Hello --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_nemotron35_host.receipt.json"  > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_nemotron35_host.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_nemotron35_host.err.txt"
echo EXIT=%ERRORLEVEL% > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_nemotron35_host.exit.txt"
