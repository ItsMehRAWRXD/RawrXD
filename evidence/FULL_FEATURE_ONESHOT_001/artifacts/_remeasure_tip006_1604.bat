@echo off
setlocal
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_006\RawrXD-Win32IDE-Native-Ext.exe
set EXPECT=5A71CA26FEF42E927A53208A374FEF8BC4FD9D3F4BF6998C596FE2026CE80211
set LOG=%LANE%\artifacts\remeasure_tip006_1604.log
echo START %DATE% %TIME% > "%LOG%"

taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >> "%LOG%" 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe /T >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul

certutil -hashfile "%EXE%" SHA256 > "%LANE%\artifacts\tip_final_006_sha_reconfirm.txt"
findstr /I /C:"%EXPECT%" "%LANE%\artifacts\tip_final_006_sha_reconfirm.txt" >nul
if errorlevel 1 (
  echo SHA_MISMATCH>> "%LOG%"
  type "%LANE%\artifacts\tip_final_006_sha_reconfirm.txt" >> "%LOG%"
  exit /b 3
)
echo SHA_MATCH=1>> "%LOG%"

powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%EXE%" -ExpectSha "%EXPECT%" -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\tip_final_006_hwnd1604" -WaitSec 90 > "%LANE%\artifacts\tip006_hwnd1604_console.txt" 2>&1
echo HARNESS_EXIT=%ERRORLEVEL%>> "%LOG%"
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >nul
type "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >> "%LOG%"
type "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt"
echo DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
