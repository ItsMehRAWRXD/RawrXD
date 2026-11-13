@echo off
setlocal
set EV=G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\AL10_AL14
set EXE=G:\~dev\rawrxd\build_ninja\bin\rawr.exe
set PHYS=G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\REAP_ALL_16GB_001\exports\MiniMax-M2.7-REAP16-CALIB-epoch1\MiniMax-M2.7-Q4_K_M-00001-of-00003.gguf
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
set RAWRXD_REAP_RETAINED=27
set WEIGHT_BUDGET_BYTES=
"%EXE%" run "%PHYS%" -p Hello --max-tokens 8 --receipt "%EV%\al10_phys.receipt.json" > "%EV%\al10_phys.out.txt" 2> "%EV%\al10_phys.err.txt"
echo EXIT=%ERRORLEVEL%> "%EV%\al10_phys.meta.txt"
endlocal
