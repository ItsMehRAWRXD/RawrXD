@echo off
setlocal EnableExtensions
set BUILD=F:\rawrxd\build_tip_debug_rel
set CAND=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts
set LOG=%OUT%\tip_panel_stay_rebuild.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
> "%LOG%" echo START %DATE% %TIME%
call "%VCVARS%" >>"%LOG%" 2>&1
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
ninja RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
if errorlevel 1 (>>"%LOG%" echo NINJA_FAIL & exit /b 2)
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
certutil -hashfile "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%OUT%\tip_panel_stay_sha.txt"
>>"%LOG%" echo DONE %DATE% %TIME%
type "%OUT%\tip_panel_stay_sha.txt"
exit /b 0
