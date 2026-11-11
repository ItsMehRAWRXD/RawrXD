@echo off
setlocal
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set SRC_BIN=%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe
set PKG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005
set CAND=%LANE%\candidates\tip_final_005
set LOG=%LANE%\artifacts\rebuild_tip005_outprob.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

echo START %DATE% %TIME% > "%LOG%"
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >> "%LOG%" 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe /T >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul

call "%VCVARS%" >> "%LOG%" 2>&1
cd /d "%BUILD%"
ninja RawrXD-Win32IDE-Native-Ext >> "%LOG%" 2>&1
if errorlevel 1 (
  echo NINJA_FAIL>> "%LOG%"
  exit /b 1
)

mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "%SRC_BIN%" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%"
copy /Y "%SRC_BIN%" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_final_005_sha.txt"
findstr /C:RAWRXD_PROBLEMS_FIXTURE "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >nul
if errorlevel 1 (echo PROBLEMS_FIXTURE_STR=0>> "%LOG%") else (echo PROBLEMS_FIXTURE_STR=1>> "%LOG%")

echo RUN_HARNESS>> "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" -ExpectSha "IGNORE" -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\tip_final_005_out_prob" -WaitSec 55 > "%LANE%\artifacts\tip005_out_prob_console.txt" 2>&1
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP005_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >nul
echo DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
