@echo off
setlocal ENABLEEXTENSIONS
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=%LANE%\package\tip_hwnd_repair_001
set CAND=%LANE%\candidates\tip_hwnd_repair_001
set LOG=%LANE%\artifacts\rebuild_tip_hwnd_repair2.log
set STATUS=%LANE%\artifacts\hwnd_repair2_status.txt
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
echo START %DATE% %TIME%> "%STATUS%"
echo START %DATE% %TIME%> "%LOG%"
if not exist "%BUILD%\build.ninja" (
  echo NO_BUILD_NINJA>> "%STATUS%"
  echo NO_BUILD_NINJA>> "%LOG%"
  exit /b 11
)
call "%VCVARS%"
if errorlevel 1 (
  echo VCVARS_FAIL>> "%STATUS%"
  exit /b 12
)
pushd "%BUILD%"
echo NINJA_BEGIN>> "%STATUS%"
ninja RawrXD-Win32IDE-Native-Ext 1>>"%LOG%" 2>>&1
set RC=%ERRORLEVEL%
popd
echo NINJA_RC=%RC%>> "%STATUS%"
if not "%RC%"=="0" (
  echo NINJA_FAIL>> "%STATUS%"
  exit /b 13
)
if not exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo EXE_MISSING_AFTER_NINJA>> "%STATUS%"
  exit /b 14
)
mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_hwnd_repair_001_sha.txt"
echo HARNESS_BEGIN>> "%STATUS%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" -ExpectSha IGNORE -OutDir "%LANE%\artifacts" -LogDir "%CAND%" -WaitSec 55 > "%LANE%\artifacts\tip_hwnd_repair_console.txt" 2>&1
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP_HWND_REPAIR_RECEIPT.txt" >nul
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\a4f_after_hwnd_repair.txt"
echo DONE>> "%STATUS%"
type "%LANE%\artifacts\TIP_HWND_REPAIR_RECEIPT.txt" >> "%STATUS%"
exit /b 0
