@echo off
setlocal EnableExtensions
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_debug_rel
set CAND=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001
set INTEG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004
set LOG=%LANE%\artifacts\tip_session_real_rebuild.log
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
> "%LOG%" echo START %DATE% %TIME%
call "%VCVARS%" >>"%LOG%" 2>&1
if errorlevel 1 (>>"%LOG%" echo VCVARS_FAIL & exit /b 91)
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
>>"%LOG%" echo NINJA_START RawrXD-Win32IDE-Native-Ext
ninja RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
if errorlevel 1 (>>"%LOG%" echo NINJA_FAIL & exit /b 2)
if not exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" (>>"%LOG%" echo EXE_MISSING & exit /b 3)
mkdir "%CAND%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%"
if exist "%INTEG%\debuggee_fixture.exe" copy /Y "%INTEG%\debuggee_fixture.exe" "%CAND%\debuggee_fixture.exe" >>"%LOG%"
certutil -hashfile "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\tip_session_real_sha.txt"
>>"%LOG%" echo DONE %DATE% %TIME%
type "%LANE%\artifacts\tip_session_real_sha.txt"
exit /b 0
