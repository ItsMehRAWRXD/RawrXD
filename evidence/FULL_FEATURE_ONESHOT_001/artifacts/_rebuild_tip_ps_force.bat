@echo off
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set BUILD=F:\rawrxd\build_tip_debug_rel
set CAND=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set LOG=%OUT%\tip_ps_force_rebuild.log
> "%LOG%" echo START %DATE% %TIME%
call "%VCVARS%" >>"%LOG%" 2>&1
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
echo TOUCH>>"%LOG%"
copy /b src\win32app\Win32IDE_PowerShellPanel.cpp+,, F:\rawrxd\src\win32app\Win32IDE_PowerShellPanel.cpp >nul 2>&1
ninja -d keepdepfile RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
echo NINJA_EXIT=%ERRORLEVEL%>>"%LOG%"
if errorlevel 1 exit /b 2
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%" 2>&1
echo COPY_EXIT=%ERRORLEVEL%>>"%LOG%"
certutil -hashfile "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%OUT%\tip_ps_routing_001_sha.txt"
type "%OUT%\tip_ps_routing_001_sha.txt"
type "%LOG%"
exit /b 0
