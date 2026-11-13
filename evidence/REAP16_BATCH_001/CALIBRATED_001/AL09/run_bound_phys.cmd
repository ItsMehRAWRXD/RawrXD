@echo off
set RAWRXD_GREEDY=1
set RAWRXD_NO_TP=1
set WEIGHT_BUDGET_MIB=32768
set DEEP2_WEIGHT_BUDGET_MIB=32768
set RAWR_SKIP_AUTO_BACKEND=1
set RAWRXD_MOE_ROUTE_TRACE=1
set RAWRXD_AL09=1
set RAWRXD_AL09_LAYER_MIN=18
set RAWRXD_AL09_TOK_MIN=3
"G:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "F:\ollamamodels\MiniMax-M2.7-REAP16-CALIB-ROUTE27\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" -p Hello --max-tokens 1 > "G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09\bound_phys.out.txt" 2> "G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09\bound_phys.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09\bound_phys.meta.txt"
