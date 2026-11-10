@echo off
setlocal EnableExtensions
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set TIP=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_003\RawrXD-Win32IDE-Native-Ext.exe
set HARNESS=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness
echo VERIFY_START> "%OUT%\verify003.txt"
if not exist "%TIP%" (
  echo TIP_MISSING>> "%OUT%\verify003.txt"
  exit /b 90
)
certutil -hashfile "%TIP%" SHA256 > "%OUT%\verify003_sha.txt"
type "%OUT%\verify003_sha.txt" >> "%OUT%\verify003.txt"

taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1

echo CHAT_BEGIN>> "%OUT%\verify003.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%HARNESS%\chat_ctrl_enter_verify.ps1" -TipExe "%TIP%" > "%OUT%\verify003_chat.txt" 2>&1
echo CHAT_RC=%ERRORLEVEL%>> "%OUT%\verify003.txt"

taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1

echo EXT_BEGIN>> "%OUT%\verify003.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%HARNESS%\ext_smoke_oneshot.ps1" -TipExe "%TIP%" > "%OUT%\verify003_ext.txt" 2>&1
echo EXT_RC=%ERRORLEVEL%>> "%OUT%\verify003.txt"

echo VERIFY_DONE>> "%OUT%\verify003.txt"
exit /b 0
