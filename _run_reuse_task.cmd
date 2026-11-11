@echo off
REM RAWRXD_CORE_DLL_NATIVE_E2E_001 - context-reuse evidence (scheduled task)
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set PROMPT=User: Tell me a very long and detailed story about a wandering programmer who never stops walking across the country. Do not stop writing until you have written at least one thousand words.

F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --reuse 8 "%PROMPT%" > %EV%\context_reuse6.log 2>&1
echo TASK_REUSE_RC=%errorlevel% >> %EV%\chain_status.txt
exit /b 0
