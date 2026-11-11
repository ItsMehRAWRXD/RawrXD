@echo off
setlocal
echo RECLAIM_START
rem Kill build/IDE by image only; no EnumWindows / WMI flood.
taskkill /F /IM ninja.exe >nul 2>&1
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM link.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE.exe >nul 2>&1
taskkill /F /IM mspdbsrv.exe >nul 2>&1
rem Excess shells from prior EnumWindows/$PID flood. Cursor recreates its own.
taskkill /F /IM powershell.exe >nul 2>&1
taskkill /F /IM pwsh.exe >nul 2>&1
echo RECLAIM_KILLS_ISSUED
cmd.exe /c echo OK
echo RECLAIM_END
endlocal
