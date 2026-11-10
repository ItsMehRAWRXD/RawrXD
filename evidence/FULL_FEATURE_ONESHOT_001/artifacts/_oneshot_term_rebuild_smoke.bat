@echo off
setlocal
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001
set VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
set LOG=%LANE%\logs\oneshot_term_rebuild_smoke.log
set STATUS=%LANE%\artifacts\oneshot_term_status.txt
echo START %DATE% %TIME%> "%STATUS%"
call "%VSDEV%" -arch=amd64 >nul
if errorlevel 1 (
  echo VSDEV_FAIL>> "%STATUS%"
  exit /b 1
)
cd /d "%BUILD%"
echo BUILD_BEGIN>> "%STATUS%"
ninja RawrXD-Win32IDE-Native-Ext > "%LOG%" 2>&1
if errorlevel 1 (
  echo NINJA_FAIL>> "%STATUS%"
  exit /b 2
)
if not exist "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" (
  echo EXE_MISSING>> "%STATUS%"
  exit /b 3
)
certutil -hashfile "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%LANE%\artifacts\oneshot_term_sha.txt"
mkdir "%LANE%\candidates\tip_final_001" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%LANE%\candidates\tip_final_001\RawrXD-Win32IDE-Native.exe" >nul
del /Q "%LANE%\artifacts\term_smoke_receipt.txt" 2>nul
del /Q F:\rawrxd\startup_trace.log 2>nul
echo SMOKE_BEGIN>> "%STATUS%"
"%LANE%\candidates\tip_final_001\RawrXD-Win32IDE-Native.exe" --term-smoke --term-quit
echo SMOKE_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\term_smoke_receipt.txt" (
  echo HAS_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\term_smoke_receipt.txt" >> "%STATUS%"
) else (
  echo HAS_RECEIPT=0>> "%STATUS%"
)
if exist F:\rawrxd\startup_trace.log type F:\rawrxd\startup_trace.log >> "%STATUS%"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\oneshot_a4f_check.txt"
echo DONE>> "%STATUS%"
exit /b 0
