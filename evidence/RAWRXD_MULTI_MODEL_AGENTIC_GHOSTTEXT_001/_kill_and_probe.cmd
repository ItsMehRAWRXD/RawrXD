@echo off
setlocal EnableExtensions
taskkill /F /IM RawrXD-Win32IDE.exe >NUL 2>&1
timeout /t 2 /nobreak >NUL
set EVID=G:\~dev\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001
set BIN=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin
cd /d "%BIN%"
del /f /q feature_probe_last.txt feature_probe_breadcrumb.txt 2>NUL
RawrXD-Win32IDE.exe --test-ghost-text
set EXITCODE=%ERRORLEVEL%
echo EXIT=%EXITCODE%> "%EVID%\FREEZE_748B_PROBE_exit.txt"
if exist feature_probe_last.txt copy /y feature_probe_last.txt "%EVID%\FREEZE_748B_PROBE_last.txt" >NUL
if exist feature_probe_breadcrumb.txt copy /y feature_probe_breadcrumb.txt "%EVID%\FREEZE_748B_PROBE_breadcrumb.txt" >NUL
echo DONE EXIT=%EXITCODE%
endlocal
