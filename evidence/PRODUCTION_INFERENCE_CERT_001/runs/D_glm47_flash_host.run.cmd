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
"g:\~dev\rawrxd\build_ninja\bin\rawr_cert_pin.exe" run "G:\~dev\rawrxd\models\_matrix_f\GLM-4.7-Flash-GGUF\GLM-4.7-Flash-Q4_K_M.gguf" -p Hello --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_glm47_flash_host.receipt.json"  > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_glm47_flash_host.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_glm47_flash_host.err.txt"
echo EXIT=%ERRORLEVEL% > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\D_glm47_flash_host.exit.txt"
