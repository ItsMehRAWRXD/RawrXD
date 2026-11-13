@echo off
set RAWRXD_HOST_DECODE=0
set R1_HOST_FLOOR=0
set RAWRXD_ALLOW_GPU=1
set DEEP2_WEIGHT_BUDGET_MIB=2048
set RAWRXD_GPU_POLICY=SOLO
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "g:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" -p Hello --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_tinyllama_gpu.receipt.json" > "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_tinyllama_gpu.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_tinyllama_gpu.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_tinyllama_gpu.exit.txt"
