@echo off
setlocal
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set BUILD=F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe
set TIPDIR=%LANE%\candidates\tip_final_005
set STATUS=%LANE%\artifacts\tip_7123_verify_status.txt
set EXTLOG=%LANE%\artifacts\verify7123_ext.txt
set A4F=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
echo START %DATE% %TIME%> "%STATUS%"
mkdir "%TIPDIR%" 2>nul
copy /Y "%BUILD%" "%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe" >nul
copy /Y "%BUILD%" "%TIPDIR%\RawrXD-Win32IDE-Native.exe" >nul
certutil -hashfile "%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%TIPDIR%\SHA256.txt"
findstr /C:WaitForDebugEvent "%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe" >nul
if errorlevel 1 (echo WFDE=0>> "%STATUS%") else (echo WFDE=1>> "%STATUS%")
findstr /C:CreatePseudoConsole "%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe" >nul
if errorlevel 1 (echo CONPTY_STR=0>> "%STATUS%") else (echo CONPTY_STR=1>> "%STATUS%")
certutil -hashfile "%A4F%" SHA256 > "%LANE%\artifacts\a4f_after_7123.txt"
echo EXT_BEGIN>> "%STATUS%"
del /Q "%LANE%\artifacts\ext_runtime_receipt.txt" 2>nul
"%TIPDIR%\RawrXD-Win32IDE-Native-Ext.exe" --ext-dir "%LANE%\fixtures\ext_hello" --ext-cmd extHello.ping --ext-quit > "%EXTLOG%" 2>&1
echo EXT_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\ext_runtime_receipt.txt" (
  echo EXT_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\ext_runtime_receipt.txt" >> "%STATUS%"
) else (
  echo EXT_RECEIPT=0>> "%STATUS%"
)
echo DONE>> "%STATUS%"
exit /b 0
