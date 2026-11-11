@echo off
setlocal
REM Rebuild HWND-repair tip WITHOUT overwriting sealed tip_final_005 CC79 or A4F.
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=%LANE%\package\tip_hwnd_repair_001
set CAND=%LANE%\candidates\tip_hwnd_repair_001
set LOG=%LANE%\artifacts\rebuild_tip_hwnd_repair.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
echo START %DATE% %TIME% > "%LOG%"
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >> "%LOG%" 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe /T >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul
call "%VCVARS%" >> "%LOG%" 2>&1
cd /d "%BUILD%"
ninja RawrXD-Win32IDE-Native-Ext >> "%LOG%" 2>&1
if errorlevel 1 ( echo NINJA_FAIL>> "%LOG%" & exit /b 1 )
mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_hwnd_repair_001_sha.txt"
findstr /C:CreatePseudoConsole "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul
echo RUN_HARNESS>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" -ExpectSha IGNORE -OutDir "%LANE%\artifacts" -LogDir "%CAND%" -WaitSec 55 > "%LANE%\artifacts\tip_hwnd_repair_console.txt" 2>&1
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP_HWND_REPAIR_RECEIPT.txt" >nul
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\a4f_after_hwnd_repair.txt"
echo DONE %DATE% %TIME%>> "%LOG%"
type "%LANE%\artifacts\TIP_HWND_REPAIR_RECEIPT.txt"
exit /b 0
