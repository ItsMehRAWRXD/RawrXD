@echo off
setlocal
set TIPDIR=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005
set OUT=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\RELAUNCH_TIP005.txt
set FIXTURE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
del /q F:\rawrxd\startup_trace.log >nul 2>&1
echo RELAUNCH_START>%OUT%
echo ASOF=%DATE% %TIME%>>%OUT%
cd /d "%TIPDIR%"
start "tip005" /D "%TIPDIR%" "RawrXD-Win32IDE-Native-Ext.exe" "%FIXTURE%"
ping -n 6 127.0.0.1 >nul
tasklist | findstr /I RawrXD >>%OUT%
echo TRACE_TAIL:>>%OUT%
if exist F:\rawrxd\startup_trace.log type F:\rawrxd\startup_trace.log >>%OUT%
echo RELAUNCH_END>>%OUT%
type %OUT%
endlocal
