@echo off
setlocal EnableExtensions
set BUILD=F:\rawrxd\build_tip_debug_rel
set CAND=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001
set PKG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_ps_routing_001
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set LOG=%OUT%\tip_ps_routing_rebuild.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
> "%LOG%" echo START %DATE% %TIME%
mkdir "%CAND%" 2>nul
mkdir "%PKG%" 2>nul
call "%VCVARS%" >>"%LOG%" 2>&1
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
ninja RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
if errorlevel 1 (>>"%LOG%" echo NINJA_FAIL & exit /b 2)
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
if exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.pdb" (
  copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.pdb" "%CAND%\RawrXD-Win32IDE-Native-Ext.pdb" >>"%LOG%"
)
certutil -hashfile "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%OUT%\tip_ps_routing_001_sha.txt"
>>"%LOG%" echo DONE %DATE% %TIME%
type "%OUT%\tip_ps_routing_001_sha.txt"
exit /b 0
