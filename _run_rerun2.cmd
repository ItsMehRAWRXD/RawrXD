@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - remaining E2E evidence after the
RAWRXD_STREAM_CANCEL_001 runtime change (orphan-launched; immune to shell
process-tree reaping, which killed the previous endurance attempt mid-pass).
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set BIN=F:\rawrxd\tmp_build_e2e

echo RERUN2_START >> %EV%\chain_status.txt

%BIN%\e2e_endurance.exe --len 512 > %EV%\endurance_512.log 2>&1
echo ENDURANCE_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --stream 64 > %EV%\streaming_64.log 2>&1
echo STREAM_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --cancel 40 > %EV%\cancellation.log 2>&1
echo CANCEL_RC=%errorlevel% >> %EV%\chain_status.txt
%BIN%\e2e_endurance.exe --reuse 8 > %EV%\context_reuse6.log 2>&1
echo REUSE_RC=%errorlevel% >> %EV%\chain_status.txt

F:\rawrxd\tmp_build_cap\stream_cancel_probe.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf 20 > %EV%\stream_cancel_probe_run.log 2>&1
echo PROBE_RC=%errorlevel% >> %EV%\chain_status.txt
echo RERUN2_COMPLETE >> %EV%\chain_status.txt
exit /b 0
