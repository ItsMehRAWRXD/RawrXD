@echo off
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_007\RawrXD-Win32IDE-Native-Ext.exe
set STATUS=%LANE%\artifacts\four_panel_007_launch.txt
echo LAUNCH %DATE% %TIME%> "%STATUS%"
if not exist "%EXE%" (
  echo EXE_MISSING>> "%STATUS%"
  exit /b 1
)
start /B "" powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\four_panel_1_17_measure.ps1" -TipExe "%EXE%" > "%LANE%\artifacts\four_panel_007_ps_out.txt" 2>&1
echo STARTED>> "%STATUS%"
exit /b 0
