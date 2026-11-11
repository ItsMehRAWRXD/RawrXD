@echo off
setlocal ENABLEEXTENSIONS
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set PKG=%LANE%\package\tip_input_event_dispatch_001
set CAND=%LANE%\candidates\tip_input_event_dispatch_001
set LOG=%LANE%\artifacts\rebuild_tip_input_event_dispatch.log
set STATUS=%LANE%\artifacts\input_event_dispatch_build_status.txt
set LOCK=%LANE%\artifacts\IDE_INPUT_EVENT_AUTOMATION.lock
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

echo START %DATE% %TIME%> "%STATUS%"
echo START %DATE% %TIME%> "%LOG%"
del "%LOCK%" >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM ninja.exe >nul 2>&1
taskkill /F /IM cl.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul

REM Force rebuild of journal + AIM input path TUs. Do NOT touch tip_hwnd_repair_001.
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE.cpp.obj" >nul 2>&1
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_lifecycle.cpp.obj" >nul 2>&1
echo TIP_INPUT_EVENT_EXCL>%LOCK%

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
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" 1>>"%LOG%"
certutil -hashfile "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_input_event_dispatch_001_sha.txt"
powershell -NoProfile -Command "$h=(Get-FileHash '%PKG%\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash; Set-Content '%PKG%\SHA256.txt' $h; Set-Content '%CAND%\SHA256.txt' $h; Add-Content '%STATUS%' ('TIP_SHA256='+$h); Write-Output $h"
REM Confirm sealed HWND tip package unchanged.
certutil -hashfile "%LANE%\package\tip_hwnd_repair_001\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_hwnd_repair_001_sha_reconfirm_after_ied.txt"
echo DONE>> "%STATUS%"
del "%LOCK%" >nul 2>&1
exit /b 0
