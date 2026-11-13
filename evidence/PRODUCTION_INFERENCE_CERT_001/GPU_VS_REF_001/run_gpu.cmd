@echo off
cd /d "g:\~dev\rawrxd\build_ninja\bin"
set RAWRXD_HOST_DECODE=
set R1_HOST_FLOOR=0
set RAWRXD_ALLOW_GPU=1
set RAWR_FORCE_GPU=1
set RAWR_NO_CPU_FALLBACK=1
set DEEP2_GPU_DEVICE_CLASS=DISCRETE
set DEEP2_GPU_POLICY=SINGLE
set WEIGHT_BUDGET_MIB=4096
set DEEP2_WEIGHT_BUDGET_MIB=4096
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "G:\~dev\rawrxd\models\tinyllama.gguf" -p Hello --max-tokens 16 > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\GPU_VS_REF_001\gpu_hello16.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\GPU_VS_REF_001\gpu_hello16.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\GPU_VS_REF_001\gpu_hello16.exit.txt"
