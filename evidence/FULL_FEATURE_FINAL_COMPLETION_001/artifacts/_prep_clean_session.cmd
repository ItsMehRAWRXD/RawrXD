@echo off
setlocal
rem Quarantine IDE session restore so tip_005 openDocument is not blocked by Unsaved Changes.
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
set L=%LOCALAPPDATA%\RawrXD
set STAMP=%DATE:~-4%%DATE:~4,2%%DATE:~7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%
set STAMP=%STAMP: =0%
if exist "%L%\ide_session.json" move /Y "%L%\ide_session.json" "%L%\ide_session.json.bak_tip005_%STAMP%"
if exist "%L%\session.state" move /Y "%L%\session.state" "%L%\session.state.bak_tip005_%STAMP%"
echo SESSION_QUARANTINED
dir /b "%L%\ide_session*" "%L%\session*"
endlocal
