@echo off
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
timeout /t 2 /nobreak >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\items_6_10\Invoke-Item678Measure.ps1" > "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\items_6_10\item678_console2.txt" 2> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\items_6_10\item678_stderr2.txt"
echo EXIT=%ERRORLEVEL%>> "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\items_6_10\item678_console2.txt"
