@echo off
set RAWRXD_GREEDY=1
set RAWRXD_NO_TP=1
set WEIGHT_BUDGET=E8B0M
set WEIGHT_BUDGET_MIB=32768
set DEEP2_WEIGHT_BUDGET_MIB=32768
set DEEP2_CHAT_TRACE=1
set RAWR_SKIP_AUTO_BACKEND=1
set RAWRXD_MOE_ROUTE_TRACE=1
set RAWRXD_AL09=1
set RAWRXD_REAP_RETAINED=256
set RAWR_REAP_SELECTION_MANIFEST=G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\selection_calib_top27.json
"G:\~dev\rawrxd\build_ninja\bin\rawr.exe" run "F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf" --reap 30GB/8 -p Hello --max-tokens 1 > "G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09\al09_full_cmd.out.txt" 2> "G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09\al09_full_cmd.err.txt"
echo EXIT=%ERRORLEVEL%> "G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\AL09\al09_full_cmd.meta.txt"
