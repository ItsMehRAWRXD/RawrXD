@echo off
cd /d "g:\~dev\rawrxd\build_ninja\bin"
set WEIGHT_BUDGET=
set E8B0M=
set RAWR_REAP_EXPORT_DIR=
set RAWR_REAP_EXPORT_EXPERIMENTAL=
set RAWRXD_DUALSTICK=
set RAWRXD_REAP_RETAINED=27
set RAWRXD_HOST_DECODE=1
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=0
set DEEP2_WEIGHT_BUDGET_MIB=59568
set WEIGHT_BUDGET_MIB=59568
"g:\~dev\rawrxd\build_ninja\bin\rawr_cert_pin.exe" run "F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" -p Hello --max-tokens 8 --receipt "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\M_minimax_full_reap16_host.receipt.json" --reap 16GB/8 > "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\M_minimax_full_reap16_host.out.txt" 2> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\M_minimax_full_reap16_host.err.txt"
set EC=%ERRORLEVEL%
> "g:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\runs\M_minimax_full_reap16_host.exit.txt" echo EXIT=%EC%