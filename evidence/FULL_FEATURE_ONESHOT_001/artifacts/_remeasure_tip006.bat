@echo off
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_006\RawrXD-Win32IDE-Native-Ext.exe
set PKG5=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >nul 2>&1
timeout /t 1 /nobreak >nul
mkdir "%PKG5%" 2>nul
copy /Y "%EXE%" "%PKG5%\RawrXD-Win32IDE-Native-Ext.exe" >nul
certutil -hashfile "%EXE%" SHA256 > "%LANE%\artifacts\tip_final_006_sha.txt"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%EXE%" -ExpectSha IGNORE -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\tip_final_006_hwnd3" -WaitSec 70 > "%LANE%\artifacts\tip006_hwnd3_console.txt" 2>&1
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >nul
type "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt"
exit /b 0
