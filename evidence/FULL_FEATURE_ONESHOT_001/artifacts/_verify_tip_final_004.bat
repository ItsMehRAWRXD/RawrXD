@echo off
setlocal EnableExtensions
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set TIP=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_004\RawrXD-Win32IDE-Native-Ext.exe
echo V4_START> "%OUT%\verify004.txt"
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
timeout /t 2 /nobreak >nul
certutil -hashfile "%TIP%" SHA256 > "%OUT%\verify004_sha.txt"
type "%OUT%\verify004_sha.txt" >> "%OUT%\verify004.txt"
echo CHAT>> "%OUT%\verify004.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%OUT%\chat_ctrl_enter_verify_e973.ps1" -TipExe "%TIP%" -LogDir "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_004" > "%OUT%\verify004_chat.txt" 2>&1
echo CHAT_RC=%ERRORLEVEL%>> "%OUT%\verify004.txt"
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo EXT>> "%OUT%\verify004.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ext_smoke_oneshot.ps1" -TipExe "%TIP%" > "%OUT%\verify004_ext.txt" 2>&1
echo EXT_RC=%ERRORLEVEL%>> "%OUT%\verify004.txt"
echo V4_DONE>> "%OUT%\verify004.txt"
exit /b 0
