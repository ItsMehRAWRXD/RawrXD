@echo off
setlocal
set TIPDIR=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005
set TIPEXE=%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe
set FIXTURE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp
set OUT=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\LAUNCH_WATCH_TIP005.txt
set ERR=%TIPDIR%\launch_stderr.txt
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
echo WATCH_START>%OUT%
echo ASOF=%DATE% %TIME%>>%OUT%
cd /d "%TIPDIR%"
rem Detach with start /wait so we get exit code without blocking agent forever if hung
start /WAIT "" "%TIPEXE%" "%FIXTURE%"
echo EXITCODE=%ERRORLEVEL%>>%OUT%
echo EXITCODE=%ERRORLEVEL%
echo WATCH_END>>%OUT%
type %OUT%
endlocal
