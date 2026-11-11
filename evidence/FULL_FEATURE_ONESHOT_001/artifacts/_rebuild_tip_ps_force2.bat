@echo off
setlocal EnableExtensions
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "BUILD=F:\rawrxd\build_tip_debug_rel"
set "CAND=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001"
set "PKG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_ps_routing_001"
set "OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts"
set "LOG=%OUT%\tip_ps_force2.log"
echo START %DATE% %TIME% > "%LOG%"
call "%VCVARS%" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo VCVARS_FAIL >> "%LOG%"
  exit /b 91
)
cd /d "%BUILD%" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo CD_FAIL >> "%LOG%"
  exit /b 1
)
echo NINJA_START >> "%LOG%"
ninja RawrXD-Win32IDE-Native-Ext >> "%LOG%" 2>&1
set "NEC=%ERRORLEVEL%"
echo NINJA_EXIT=%NEC% >> "%LOG%"
if not "%NEC%"=="0" exit /b 2
if not exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo EXE_MISSING >> "%LOG%"
  exit /b 3
)
mkdir "%CAND%" 2>nul
mkdir "%PKG%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%" 2>&1
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%PKG%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%" 2>&1
certutil -hashfile "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%OUT%\tip_ps_routing_001_sha.txt"
echo DONE %DATE% %TIME% >> "%LOG%"
type "%OUT%\tip_ps_routing_001_sha.txt"
type "%LOG%"
exit /b 0
