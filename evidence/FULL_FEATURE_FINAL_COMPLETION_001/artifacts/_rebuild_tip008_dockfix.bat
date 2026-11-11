@echo off
setlocal ENABLEEXTENSIONS
set LOG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\rebuild_tip008_dockfix.log
set BUILD=F:\rawrxd\build_tip_ext_host_001
set OUT=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008
echo ====DOCKFIX %DATE% %TIME%>"%LOG%"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >>"%LOG%" 2>&1
REM WRL lives under winrt\; ensure INCLUDE even if vcvars omits it.
set "INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\winrt;%INCLUDE%"
echo INCLUDE_HEAD>>"%LOG%"
echo %INCLUDE%>>"%LOG%"
cd /d "%BUILD%"
echo PWD=%CD%>>"%LOG%"
REM Force VSCodeUI + header-dependent units to rebuild for layoutBottomDock.
del /q "CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_VSCodeUI.cpp.obj" 2>nul
del /q "CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_Commands.cpp.obj" 2>nul
ninja -j1 RawrXD-Win32IDE-Native-Ext >>"%LOG%" 2>&1
set RC=%ERRORLEVEL%
echo NINJA_EXIT=%RC%>>"%LOG%"
if not "%RC%"=="0" exit /b %RC%
if not exist "bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo MISSING_EXE>>"%LOG%"
  exit /b 2
)
mkdir "%OUT%" 2>nul
copy /Y "bin\RawrXD-Win32IDE-Native-Ext.exe" "%OUT%\RawrXD-Win32IDE-Native-Ext.exe" >>"%LOG%" 2>&1
if exist "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_007\debuggee_fixture.exe" (
  copy /Y "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_007\debuggee_fixture.exe" "%OUT%\debuggee_fixture.exe" >>"%LOG%" 2>&1
) else if exist "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005\debuggee_fixture.exe" (
  copy /Y "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005\debuggee_fixture.exe" "%OUT%\debuggee_fixture.exe" >>"%LOG%" 2>&1
)
powershell -NoProfile -Command "(Get-FileHash '%OUT%\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash | Set-Content -LiteralPath '%OUT%\SHA256.txt' -Encoding ASCII" >>"%LOG%" 2>&1
type "%OUT%\SHA256.txt" >>"%LOG%"
findstr /C:"G7_layoutBottomDock_SetWindowPos_1300" "%OUT%\RawrXD-Win32IDE-Native-Ext.exe" >nul && echo MARKER_LAYOUT=1>>"%LOG%" || echo MARKER_LAYOUT=0>>"%LOG%"
echo DONE>>"%LOG%"
exit /b 0
