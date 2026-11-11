@echo off
setlocal EnableExtensions
set BUILD=F:\rawrxd\build_tip_debug_rel
set CAND=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001
set PKG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set LOG=%OUT%\tip_integ_candidate_001_rebuild.log
set STATUS=%OUT%\tip_integ_candidate_001_build_status.txt
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat

> "%STATUS%" echo START %DATE% %TIME%
> "%LOG%" echo START %DATE% %TIME%
mkdir "%CAND%" 2>nul
mkdir "%PKG%" 2>nul

REM Do not touch sealed tip006 / A4F / CC79 / tip_hwnd_repair_001 packages.
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM ninja.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul

REM Force rebuild of absorbed fix TUs only.
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_PowerShellPanel.cpp.obj" >nul 2>&1
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_AgentStepTimeline.cpp.obj" >nul 2>&1
del /F /Q "%BUILD%\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_lifecycle.cpp.obj" >nul 2>&1

call "%VCVARS%" >>"%LOG%" 2>&1
if errorlevel 1 (
  >>"%STATUS%" echo VCVARS_FAIL
  exit /b 12
)
cd /d "%BUILD%" || (>>"%STATUS%" echo CD_FAIL & exit /b 1)
>>"%STATUS%" echo NINJA_BEGIN
ninja RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
set RC=%ERRORLEVEL%
>>"%STATUS%" echo NINJA_RC=%RC%
if not "%RC%"=="0" (
  >>"%STATUS%" echo NINJA_FAIL
  exit /b 13
)

copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
if exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.pdb" (
  copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.pdb" "%CAND%\RawrXD-Win32IDE-Native-Ext.pdb" >>"%LOG%"
)

powershell -NoProfile -Command "$h=(Get-FileHash '%PKG%\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash; Set-Content '%PKG%\SHA256.txt' $h; Set-Content '%CAND%\SHA256.txt' $h; Set-Content '%OUT%\tip_integ_candidate_001_sha.txt' $h; Add-Content '%STATUS%' ('TIP_SHA256='+$h); Write-Output $h"
>>"%LOG%" echo DONE %DATE% %TIME%
>>"%STATUS%" echo DONE
type "%OUT%\tip_integ_candidate_001_sha.txt"
exit /b 0
