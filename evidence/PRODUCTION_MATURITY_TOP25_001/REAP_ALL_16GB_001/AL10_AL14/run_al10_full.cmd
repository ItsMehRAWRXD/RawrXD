@echo off
setlocal
set EV=G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\AL10_AL14
set EXE=G:\~dev\rawrxd\build_ninja\bin\rawr.exe
set FULL=F:\ollamamodels\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf
set MAN=G:\~dev\rawrxd\evidence\REAP16_BATCH_001\CALIBRATED_001\selection_calib_top27.json
taskkill /F /IM rawr.exe /T >nul 2>&1
ping -n 4 127.0.0.1 >nul
set RAWRXD_AL10=1
set RAWRXD_AL09=1
set RAWRXD_GREEDY=1
set RAWRXD_RAW_PROMPT=1
set RAWRXD_NO_TP=1
set RAWR_SKIP_AUTO_BACKEND=1
set RAWRXD_HOST_DECODE=1
set RAWRXD_MOE_ROUTE_TRACE=1
set WEIGHT_BUDGET_MIB=59568
set DEEP2_WEIGHT_BUDGET_MIB=59568
set RAWRXD_REAP_RETAINED=256
set RAWR_REAP_SELECTION_MANIFEST=%MAN%
set WEIGHT_BUDGET_BYTES=
"%EXE%" run "%FULL%" --reap 30GB/8 -p Hello --max-tokens 8 --receipt "%EV%\al10_full.receipt.json" > "%EV%\al10_full.out.txt" 2> "%EV%\al10_full.err.txt"
echo EXIT=%ERRORLEVEL%> "%EV%\al10_full.meta.txt"
endlocal
