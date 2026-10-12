@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - remaining E2E evidence chain
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set BIN=F:\rawrxd\tmp_build_e2e

F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --len 512 > %EV%\endurance_512.log 2>&1
echo ENDURANCE_RC=%errorlevel% >> %EV%\chain_status.txt
F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --stream 64 > %EV%\streaming_64.log 2>&1
echo STREAM_RC=%errorlevel% >> %EV%\chain_status.txt
F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --cancel 40 > %EV%\cancellation.log 2>&1
echo CANCEL_RC=%errorlevel% >> %EV%\chain_status.txt
F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --reuse 8 > %EV%\context_reuse6.log 2>&1
echo REUSE_RC=%errorlevel% >> %EV%\chain_status.txt
echo CHAIN_COMPLETE >> %EV%\chain_status.txt
exit /b 0
