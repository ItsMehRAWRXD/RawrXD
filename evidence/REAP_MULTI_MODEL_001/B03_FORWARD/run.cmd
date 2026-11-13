@echo off
set R1_HOST_FLOOR=1
set RAWRXD_ALLOW_GPU=
set WEIGHT_BUDGET_MIB=
set DEEP2_WEIGHT_BUDGET_MIB=
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" --reap 30GB/8 -p Hello --max-tokens 4 --receipt "g:\~dev\rawrxd\evidence\REAP_MULTI_MODEL_001\B03_FORWARD\minimax_b03.json" > "g:\~dev\rawrxd\evidence\REAP_MULTI_MODEL_001\B03_FORWARD\minimax_b03.out.txt" 2> "g:\~dev\rawrxd\evidence\REAP_MULTI_MODEL_001\B03_FORWARD\minimax_b03.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\REAP_MULTI_MODEL_001\B03_FORWARD\minimax_b03.exit.txt"
