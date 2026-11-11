@echo off
setlocal
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_007\RawrXD-Win32IDE-Native-Ext.exe
set STATUS=%LANE%\artifacts\measure_1f60_status.txt
echo START %DATE% %TIME%> "%STATUS%"
if not exist "%EXE%" ( echo EXE_MISSING>> "%STATUS%" & exit /b 1 )
certutil -hashfile "%EXE%" SHA256 > "%LANE%\artifacts\measure_1f60_sha.txt"
findstr /C:WaitForDebugEvent "%EXE%" >nul
if errorlevel 1 (echo WFDE=0>> "%STATUS%") else (echo WFDE=1>> "%STATUS%")
findstr /C:CreatePseudoConsole "%EXE%" >nul
if errorlevel 1 (echo CONPTY_STR=0>> "%STATUS%") else (echo CONPTY_STR=1>> "%STATUS%")
taskkill /F /IM RawrXD-Win32IDE-Native* >nul 2>&1
del /Q "%LANE%\artifacts\term_smoke_receipt.txt" 2>nul
"%EXE%" --term-smoke --term-quit
echo TERM_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\term_smoke_receipt.txt" (
  echo TERM_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\term_smoke_receipt.txt" >> "%STATUS%"
  copy /Y "%LANE%\artifacts\term_smoke_receipt.txt" "%LANE%\artifacts\term_smoke_receipt_1F60.txt" >nul
) else ( echo TERM_RECEIPT=0>> "%STATUS%" )
del /Q "%LANE%\artifacts\ext_runtime_receipt.txt" 2>nul
"%EXE%" --ext-dir "%LANE%\fixtures\ext_hello" --ext-cmd extHello.ping --ext-quit
echo EXT_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\ext_runtime_receipt.txt" (
  echo EXT_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\ext_runtime_receipt.txt" >> "%STATUS%"
  copy /Y "%LANE%\artifacts\ext_runtime_receipt.txt" "%LANE%\artifacts\ext_runtime_receipt_1F60.txt" >nul
) else ( echo EXT_RECEIPT=0>> "%STATUS%" )
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\a4f_after_1f60.txt"
echo DONE>> "%STATUS%"
exit /b 0
