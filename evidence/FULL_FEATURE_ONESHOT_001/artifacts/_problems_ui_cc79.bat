@echo off
setlocal EnableExtensions
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set LOG=%LANE%\artifacts\problems_ui_cc79_run.log
set RECEIPT=%LANE%\PROBLEMS_UI_CC79_RECEIPT.md
set EXPECT=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
set FIXTURE=%LANE%\fixtures\broken_multi.cpp
set TIP=
if exist "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe" set TIP=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
if not defined TIP if exist "F:\rawrxd\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe" set TIP=F:\rawrxd\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
if not defined TIP if exist "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe" set TIP=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe

echo START %DATE% %TIME%> "%LOG%"
echo TIP=%TIP%>> "%LOG%"
if not defined TIP (
  echo BLOCKER=tip_exe_missing>> "%LOG%"
  exit /b 2
)

certutil -hashfile "%TIP%" SHA256 > "%LANE%\artifacts\problems_ui_cc79_sha.txt"
findstr /I /C:"%EXPECT%" "%LANE%\artifacts\problems_ui_cc79_sha.txt" >nul
if errorlevel 1 (
  echo SHA_MISMATCH expect=%EXPECT%>> "%LOG%"
) else (
  echo SHA_MATCH=1>> "%LOG%"
)

findstr /C:RAWRXD_PROBLEMS_FIXTURE "%TIP%" >nul
if errorlevel 1 (
  echo FIXTURE_STR=0>> "%LOG%"
  echo NOTE=CC79 image lacks PROBLEMS_FIXTURE; rebuild tip_final_integ_003 required>> "%LOG%"
) else (
  echo FIXTURE_STR=1>> "%LOG%"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\problems_gui_measure_007.ps1" -TipExe "%TIP%" -BrokenCpp "%FIXTURE%" -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\problems_ui_cc79" -WaitSec 70 > "%LANE%\artifacts\problems_ui_cc79_console.txt" 2>&1
echo HARNESS_EXIT=%ERRORLEVEL%>> "%LOG%"
echo DONE %DATE% %TIME%>> "%LOG%"
exit /b 0
