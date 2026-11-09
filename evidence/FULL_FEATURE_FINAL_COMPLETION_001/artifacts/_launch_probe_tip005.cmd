@echo off
setlocal EnableExtensions
set TIPDIR=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005
set TIPEXE=%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe
set FIXTURE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp
set OUT=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\LAUNCH_PROBE_TIP005.txt
set LOGDIR=%TIPDIR%\logs
echo LAUNCH_PROBE_START>%OUT%
echo ASOF=%DATE% %TIME%>>%OUT%
certutil -hashfile "%TIPEXE%" SHA256 >>%OUT% 2>&1
if not exist "%TIPEXE%" (
  echo EXE_MISSING=1>>%OUT%
  echo EXE_MISSING
  exit /b 2
)
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
set RAWRXD_LOG_DIR=%LOGDIR%
cd /d "%TIPDIR%"
echo STARTING=%TIPEXE%>>%OUT%
start "" /D "%TIPDIR%" "%TIPEXE%" "%FIXTURE%"
rem Wait without WMI/EnumWindows flood
ping -n 6 127.0.0.1 >nul
tasklist /FI "IMAGENAME eq RawrXD-Win32IDE-Native-Ext.exe" >>%OUT% 2>&1
tasklist /FI "IMAGENAME eq RawrXD-Win32IDE-Native-Ext.exe" | find /I "RawrXD-Win32IDE-Native-Ext.exe" >nul
if errorlevel 1 (
  echo ALIVE=0>>%OUT%
  echo EXIT_EARLY=1>>%OUT%
  echo ALIVE=0
) else (
  echo ALIVE=1>>%OUT%
  echo ALIVE=1
)
rem Second settle
ping -n 4 127.0.0.1 >nul
tasklist /FI "IMAGENAME eq RawrXD-Win32IDE-Native-Ext.exe" >>%OUT% 2>&1
tasklist /FI "IMAGENAME eq RawrXD-Win32IDE-Native-Ext.exe" | find /I "RawrXD-Win32IDE-Native-Ext.exe" >nul
if errorlevel 1 (
  echo ALIVE2=0>>%OUT%
) else (
  echo ALIVE2=1>>%OUT%
)
echo LAUNCH_PROBE_END>>%OUT%
type %OUT%
endlocal
