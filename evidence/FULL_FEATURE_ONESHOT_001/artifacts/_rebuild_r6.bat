@echo off
setlocal EnableExtensions
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set BUILD=F:\rawrxd\build_tip_debug_rel
set LOG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_rebuild_r6.log
set PKG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001
set CAND=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001
> "%LOG%" echo START %DATE% %TIME%
call "%VCVARS%" >>"%LOG%" 2>&1
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
del /F /Q "CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_PowerShellPanel.cpp.obj" >nul 2>&1
echo COMPILE_BEGIN>>"%LOG%"
ninja "CMakeFiles/RawrXD-Win32IDE-Native-Ext.dir/src/win32app/Win32IDE_PowerShellPanel.cpp.obj" >>"%LOG%" 2>&1
echo COMPILE_RC=%ERRORLEVEL%>>"%LOG%"
if errorlevel 1 exit /b 2
echo LINK_BEGIN>>"%LOG%"
REM Prefer direct link of EXE target; if shaders dirty this may cascade — still attempt.
ninja bin/RawrXD-Win32IDE-Native-Ext.exe >>"%LOG%" 2>&1
echo LINK_RC=%ERRORLEVEL%>>"%LOG%"
if errorlevel 1 exit /b 3
mkdir "%PKG%" 2>nul
mkdir "%CAND%" 2>nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
powershell -NoProfile -Command "$h=(Get-FileHash '%PKG%\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash; Set-Content '%PKG%\SHA256.txt' $h; Set-Content '%CAND%\SHA256.txt' $h; Set-Content 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\tip_integ_candidate_001_sha.txt' $h; @('TIP_PACKAGE=tip_integ_candidate_001','TIP_SHA256='+$h,'REASON=PS_WM_COPYDATA_CMD_DELIVERY','REPLACEMENT_OF=F83CA2705E98F9610AC2A730B0A75F7D9524B038CBB2A5435038379947B223C5','PROMOTE=0') | Set-Content '%PKG%\META.txt'; Write-Output $h"
echo DONE %DATE% %TIME%>>"%LOG%"
exit /b 0
