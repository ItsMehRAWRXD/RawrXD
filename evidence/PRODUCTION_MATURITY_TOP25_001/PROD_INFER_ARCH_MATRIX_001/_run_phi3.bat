@echo off
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set DEEP2_WEIGHT_BUDGET_MIB=4096
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "g:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf" -p Hello --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_phi3_mini_host.receipt.json" > "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_phi3_mini_host.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_phi3_mini_host.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_phi3_mini_host.exit.txt"
