@echo off
setlocal ENABLEEXTENSIONS
REM CC79_RUNTIME_001 — new tip for Output→four-panel measure.
REM Does NOT overwrite CC79 tip_final_005, A4F, tip_hwnd_repair_001, tip_final_006 seals.
set LANE=F:\rawrxd\evidence\CC79_RUNTIME_001
set ONESHOT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=%LANE%\package\tip_cc79_integ_001
set CAND=%LANE%\candidates\tip_cc79_integ_001
set LOG=%LANE%\artifacts\rebuild_tip_cc79_integ_001.log
set STATUS=%LANE%\artifacts\rebuild_status.txt
set LOCK=%ONESHOT%\artifacts\IDE_HWND_AUTOMATION.lock
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

mkdir "%LANE%\artifacts" 2>nul
mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul

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
echo CC79_RUNTIME_EXCL>%LOCK%

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

copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_cc79_integ_001_sha.txt"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\cc79_sha_reconfirm.txt"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\a4f_sha_reconfirm.txt"
certutil -hashfile "%ONESHOT%\package\tip_hwnd_repair_001\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_hwnd_repair_001_sha_reconfirm.txt"

echo BUILD_DONE>> "%STATUS%"
del "%LOCK%" >nul 2>&1
exit /b 0
