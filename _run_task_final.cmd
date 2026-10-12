@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - endurance + streaming probe via a
REM detached scheduled task (own console; the tool shell's Ctrl+C and
REM process-tree cleanup otherwise kill console-sharing children mid-pass).
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001

echo TASK_START >> %EV%\chain_status.txt

F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --len 512 > %EV%\endurance_512.log 2>&1
echo TASK_ENDURANCE_RC=%errorlevel% >> %EV%\chain_status.txt

F:\rawrxd\tmp_build_cap\stream_cancel_probe.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf 20 > %EV%\stream_cancel_probe_run.log 2>&1
echo TASK_PROBE_RC=%errorlevel% >> %EV%\chain_status.txt

echo TASK_COMPLETE >> %EV%\chain_status.txt
exit /b 0
