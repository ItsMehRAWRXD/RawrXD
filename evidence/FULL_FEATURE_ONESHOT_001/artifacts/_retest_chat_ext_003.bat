@echo off
setlocal EnableExtensions
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set TIP=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_003\RawrXD-Win32IDE-Native-Ext.exe
set H=%OUT%\..\harness
echo RETEST2_START> "%OUT%\retest2.txt"
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo CHAT>> "%OUT%\retest2.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%H%\chat_ctrl_enter_verify.ps1" -TipExe "%TIP%" -LogDir "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_003" > "%OUT%\retest2_chat.txt" 2>&1
echo CHAT_RC=%ERRORLEVEL%>> "%OUT%\retest2.txt"
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo EXT>> "%OUT%\retest2.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%H%\ext_smoke_oneshot.ps1" -TipExe "%TIP%" > "%OUT%\retest2_ext.txt" 2>&1
echo EXT_RC=%ERRORLEVEL%>> "%OUT%\retest2.txt"
echo RETEST2_DONE>> "%OUT%\retest2.txt"
exit /b 0
