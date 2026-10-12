@echo off
REM Clean, isolated cancellation + post-cancel reuse evidence (own console,
REM unique log file, then moved into place so a concurrent writer can never
REM truncate it).
setlocal
set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
set PROMPT=User: Tell me a very long and detailed story about a wandering programmer who never stops walking across the country. Do not stop writing until you have written at least one thousand words.

F:\rawrxd\tmp_build_e2e\e2e_endurance.exe --cancel 40 "%PROMPT%" > %EV%\.cancel_clean.log 2>&1
set RC=%errorlevel%
echo CANCEL_CLEAN_RC=%RC% >> %EV%\cancel_clean_status.txt
if "%RC%"=="0" move /y %EV%\.cancel_clean.log %EV%\cancellation.log >nul
echo CANCEL_CLEAN_DONE >> %EV%\cancel_clean_status.txt
exit /b 0
