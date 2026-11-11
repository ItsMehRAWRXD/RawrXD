@echo off
setlocal EnableExtensions
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_006
set CAND=%LANE%\candidates\tip_final_006
set LOG=%LANE%\artifacts\tip006_rebuild_measure.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

> "%LOG%" echo START %DATE% %TIME%
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >>"%LOG%" 2>&1
timeout /t 1 /nobreak >nul

call "%VCVARS%" >nul 2>&1
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
>>"%LOG%" echo NINJA_START
ninja RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
if errorlevel 1 (>>"%LOG%" echo NINJA_FAIL & exit /b 2)
if not exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" (>>"%LOG%" echo EXE_MISSING & exit /b 3)

mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_final_006_sha.txt"
findstr /C:RAWRXD_PROBLEMS_FIXTURE "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul && (>>"%LOG%" echo FIXTURE_STR=1) || (>>"%LOG%" echo FIXTURE_STR=0)
findstr /C:dispatch_id= "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul && (>>"%LOG%" echo DISPATCH_ID_STR=1) || (>>"%LOG%" echo DISPATCH_ID_STR=0)

>>"%LOG%" echo HARNESS_START
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" -ExpectSha IGNORE -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\tip_final_006_hwnd" -WaitSec 65 > "%LANE%\artifacts\tip006_hwnd_console.txt" 2>&1
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >nul
>>"%LOG%" echo DONE %DATE% %TIME%
type "%LANE%\artifacts\TIP006_OUTPUT_PROBLEMS_HWND_RECEIPT.txt"
exit /b 0
