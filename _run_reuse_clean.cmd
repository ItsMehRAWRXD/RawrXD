@echo off
REM Clean, isolated context-reuse evidence run (own console, unique log file,
REM then moved into place so a concurrent writer can never truncate it).
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set PROMPT=User: Tell me a very long and detailed story about a wandering programmer who never stops walking across the country. Do not stop writing until you have written at least one thousand words.

F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --reuse 8 "%PROMPT%" > %EV%\.reuse_clean.log 2>&1
set RC=%errorlevel%
echo REUSE_CLEAN_RC=%RC% >> %EV%\reuse_clean_status.txt
if "%RC%"=="0" move /y %EV%\.reuse_clean.log %EV%\context_reuse6.log >nul
echo REUSE_CLEAN_DONE >> %EV%\reuse_clean_status.txt
exit /b 0
