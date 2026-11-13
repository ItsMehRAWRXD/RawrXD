@echo off
set DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1=1
"g:\~dev\rawrxd\build_ninja\bin\deep2_gpu_packed_forward_cert.exe" "g:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" > "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_gpu_packed_cert.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_gpu_packed_cert.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\PROD_INFER_ARCH_MATRIX_001\R2_gpu_packed_cert.exit.txt"
