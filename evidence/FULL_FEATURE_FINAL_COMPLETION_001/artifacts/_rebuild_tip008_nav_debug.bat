@echo off
setlocal ENABLEEXTENSIONS
REM tip_008 nav+H02 rebuild. Does NOT touch tip_005 27E2263E or chat build_tip_debug_rel.
set LOG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\rebuild_tip008_nav_debug.log
set BUILD=F:\rawrxd\build_tip_ext_host_001
set OUT=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008
echo ====RESTART %DATE% %TIME%>"%LOG%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >>"%LOG%" 2>&1
cd /d "%BUILD%"
echo PWD=%CD%>>"%LOG%"
where ninja >>"%LOG%" 2>&1
echo NINJA_START>>"%LOG%"
ninja RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
set RC=%ERRORLEVEL%
echo NINJA_EXIT=%RC%>>"%LOG%"
if not "%RC%"=="0" exit /b %RC%
if not exist "bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo MISSING_EXE>>"%LOG%"
  exit /b 2
)
mkdir "%OUT%" 2>nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%OUT%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%" 2>&1
REM Carry tip_005 debuggee fixture if present
if exist "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005\debuggee_fixture.exe" (
  copy /Y "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005\debuggee_fixture.exe" "%OUT%\debuggee_fixture.exe" >>"%LOG%" 2>&1
)
powershell -NoProfile -Command "(Get-FileHash '%OUT%\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash | Set-Content -LiteralPath '%OUT%\SHA256.txt' -Encoding ASCII" >>"%LOG%" 2>&1
type "%OUT%\SHA256.txt" >>"%LOG%"
echo DONE>>"%LOG%"
exit /b 0
