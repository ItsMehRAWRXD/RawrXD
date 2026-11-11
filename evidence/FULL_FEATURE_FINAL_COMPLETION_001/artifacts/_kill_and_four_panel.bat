@echo off
setlocal
echo KILL_BEGIN %DATE% %TIME%
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe /T >nul 2>&1
timeout /t 3 /nobreak >nul
echo KILL_DONE %TIME%
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\run_integ007_four_panel_reverify.ps1" > "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\integ007_four_panel_console_rerun.txt" 2>&1
echo FOUR_EXIT=%ERRORLEVEL% %TIME%
echo POST_SHA>
powershell -NoProfile -Command "(Get-FileHash 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_007\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash"
endlocal
