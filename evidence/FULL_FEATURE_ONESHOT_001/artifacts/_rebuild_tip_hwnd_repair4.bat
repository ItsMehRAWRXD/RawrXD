@echo off
setlocal ENABLEEXTENSIONS
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=%LANE%\package\tip_hwnd_repair_001
set PKG7=%LANE%\package\tip_final_007
set CAND=%LANE%\candidates\tip_hwnd_repair_001
set LOG=%LANE%\artifacts\rebuild_tip_hwnd_repair4.log
set STATUS=%LANE%\artifacts\hwnd_repair4_status.txt
set LOCK=%LANE%\artifacts\IDE_HWND_AUTOMATION.lock
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

echo START %DATE% %TIME%> "%STATUS%"
echo START %DATE% %TIME%> "%LOG%"
del "%LOCK%" >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM ninja.exe >nul 2>&1
taskkill /F /IM cl.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul

del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE.cpp.obj" >nul 2>&1
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_Core.cpp.obj" >nul 2>&1
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_lifecycle.cpp.obj" >nul 2>&1
echo TIP005_EXCL>%LOCK%

call "%VCVARS%" >>"%LOG%" 2>&1
if errorlevel 1 (
  echo VCVARS_FAIL>> "%STATUS%"
  del "%LOCK%" >nul 2>&1
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
  del "%LOCK%" >nul 2>&1
  exit /b 13
)

mkdir "%PKG%" 2>nul
mkdir "%PKG7%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG7%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_hwnd_repair_001_sha.txt"
certutil -hashfile "%PKG7%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_final_007_sha.txt"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\a4f_after_hwnd_repair.txt"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\cc79_after_hwnd_repair.txt"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_006\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_final_006_sha_reconfirm.txt"

echo HARNESS_BEGIN>> "%STATUS%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\ea5d_output_problems_hwnd.ps1" -TipExe "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" -ExpectSha IGNORE -OutDir "%LANE%\artifacts" -LogDir "%CAND%" -WaitSec 90 > "%LANE%\artifacts\tip_hwnd_repair_console.txt" 2>&1
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP_HWND_REPAIR_RECEIPT.txt" >nul
copy /Y "%LANE%\artifacts\EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" "%LANE%\artifacts\TIP007_OUTPUT_PROBLEMS_HWND_RECEIPT.txt" >nul
echo DONE>> "%STATUS%"
type "%LANE%\artifacts\TIP_HWND_REPAIR_RECEIPT.txt" >> "%STATUS%"
del "%LOCK%" >nul 2>&1
exit /b 0
