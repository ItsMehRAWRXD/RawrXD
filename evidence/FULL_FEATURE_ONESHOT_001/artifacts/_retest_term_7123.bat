@echo off
setlocal
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=%LANE%\candidates\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
set STATUS=%LANE%\artifacts\retest_term_7123.txt
echo START %DATE% %TIME%> "%STATUS%"
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
del /Q "%LANE%\artifacts\term_smoke_receipt.txt" 2>nul
del /Q F:\rawrxd\startup_trace.log 2>nul
"%EXE%" --term-smoke --term-quit
echo EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\term_smoke_receipt.txt" (
  echo HAS_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\term_smoke_receipt.txt" >> "%STATUS%"
) else (
  echo HAS_RECEIPT=0>> "%STATUS%"
)
if exist F:\rawrxd\startup_trace.log type F:\rawrxd\startup_trace.log >> "%STATUS%"
echo DONE>> "%STATUS%"
exit /b 0
