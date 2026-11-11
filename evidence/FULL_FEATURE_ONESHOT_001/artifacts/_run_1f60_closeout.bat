@echo off
setlocal EnableExtensions
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_007\RawrXD-Win32IDE-Native-Ext.exe
set EXPECT=1F6005131BA855B994C6D05009A7052781D289EFF197E7F5E709C947B0F53E04
set LOG=%LANE%\artifacts\run_1f60_closeout.log
set STATUS=%LANE%\artifacts\measure_1f60_status.txt
set MASTER=%LANE%\artifacts\MEASURED_1F60_CLOSEOUT.txt
echo ===== START %DATE% %TIME% > "%LOG%"
echo START %DATE% %TIME%> "%STATUS%"

REM --- kill hung ---
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe /T >> "%LOG%" 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe /T >> "%LOG%" 2>&1
timeout /t 2 /nobreak >nul
echo TASKKILL_DONE>> "%STATUS%"

if not exist "%EXE%" (
  echo EXE_MISSING>> "%STATUS%"
  echo EXE_MISSING> "%MASTER%"
  exit /b 1
)

certutil -hashfile "%EXE%" SHA256 > "%LANE%\artifacts\measure_1f60_sha.txt"
findstr /I /C:"%EXPECT%" "%LANE%\artifacts\measure_1f60_sha.txt" >nul
if errorlevel 1 (
  echo SHA_MISMATCH>> "%STATUS%"
  echo SHA_MISMATCH> "%MASTER%"
  type "%LANE%\artifacts\measure_1f60_sha.txt" >> "%MASTER%"
) else (
  echo SHA_MATCH=1>> "%STATUS%"
  echo TIP_SHA256=%EXPECT%>> "%STATUS%"
)

findstr /C:WaitForDebugEvent "%EXE%" >nul
if errorlevel 1 (echo WFDE=0>> "%STATUS%") else (echo WFDE=1>> "%STATUS%")
findstr /C:CreatePseudoConsole "%EXE%" >nul
if errorlevel 1 (echo CONPTY_STR=0>> "%STATUS%") else (echo CONPTY_STR=1>> "%STATUS%")

REM --- Terminal ConPTY smoke ---
del /Q "%LANE%\artifacts\term_smoke_receipt.txt" 2>nul
"%EXE%" --term-smoke --term-quit >> "%LOG%" 2>&1
echo TERM_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\term_smoke_receipt.txt" (
  echo TERM_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\term_smoke_receipt.txt" >> "%STATUS%"
  copy /Y "%LANE%\artifacts\term_smoke_receipt.txt" "%LANE%\artifacts\term_smoke_receipt_1F60.txt" >nul
) else (
  echo TERM_RECEIPT=0>> "%STATUS%"
)

REM --- EXT lifecycle ---
del /Q "%LANE%\artifacts\ext_runtime_receipt.txt" 2>nul
"%EXE%" --ext-dir "%LANE%\fixtures\ext_hello" --ext-cmd extHello.ping --ext-quit >> "%LOG%" 2>&1
echo EXT_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\ext_runtime_receipt.txt" (
  echo EXT_RECEIPT=1>> "%STATUS%"
  type "%LANE%\artifacts\ext_runtime_receipt.txt" >> "%STATUS%"
  copy /Y "%LANE%\artifacts\ext_runtime_receipt.txt" "%LANE%\artifacts\ext_runtime_receipt_1F60.txt" >nul
) else (
  echo EXT_RECEIPT=0>> "%STATUS%"
)

REM --- A4F untouched check (hash file only; never overwrite) ---
if exist "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" (
  certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 > "%LANE%\artifacts\a4f_after_1f60.txt"
)

REM --- Chat AIM 7/7 ---
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\chat_ctrl_enter_verify.ps1" -TipExe "%EXE%" -OutDir "%LANE%\artifacts" -LogDir "%LANE%\candidates\tip_chat_1f60" >> "%LOG%" 2>&1
echo CHAT_HARNESS_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\CHAT_CTRL_ENTER_RECEIPT.txt" (
  copy /Y "%LANE%\artifacts\CHAT_CTRL_ENTER_RECEIPT.txt" "%LANE%\artifacts\CHAT_CTRL_ENTER_RECEIPT_1F60.txt" >nul
  type "%LANE%\artifacts\CHAT_CTRL_ENTER_RECEIPT.txt" >> "%STATUS%"
)

REM --- Debug backend verify if present beside tip or build ---
set DBGVER=
if exist "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_007\debug_backend_verify.exe" set DBGVER=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_007\debug_backend_verify.exe
if not defined DBGVER if exist "F:\rawrxd\build_tip_ext_host_001\bin\debug_backend_verify.exe" set DBGVER=F:\rawrxd\build_tip_ext_host_001\bin\debug_backend_verify.exe
if defined DBGVER (
  echo DBGVER=%DBGVER%>> "%STATUS%"
  "%DBGVER%" > "%LANE%\artifacts\debug_backend_verify_1F60.txt" 2>&1
  echo DEBUG_VERIFY_EXIT=%ERRORLEVEL%>> "%STATUS%"
  type "%LANE%\artifacts\debug_backend_verify_1F60.txt" >> "%STATUS%"
) else (
  echo DBGVER=MISSING>> "%STATUS%"
  echo DEBUG_VERIFY_EXIT=NOT_RUN>> "%STATUS%"
)

REM --- Four-panel 1-17 ---
taskkill /F /IM RawrXD-Win32IDE-Native* >nul 2>&1
timeout /t 1 /nobreak >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%LANE%\harness\four_panel_1_17_measure.ps1" -TipExe "%EXE%" >> "%LOG%" 2>&1
echo FOUR_PANEL_HARNESS_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\FOUR_PANEL_1_17_RECEIPT.txt" (
  type "%LANE%\artifacts\FOUR_PANEL_1_17_RECEIPT.txt" >> "%STATUS%"
)

echo DONE %DATE% %TIME%>> "%STATUS%"
echo DONE>> "%LOG%"

REM --- master rollup ---
(
  echo ASOF=%DATE% %TIME%
  echo CHOSEN_SHA256=%EXPECT%
  echo TIP_EXE=%EXE%
  echo PROMOTE=0
  echo CERTIFIED=0
  echo PRODUCT_PASS=0
  echo TIP_FIX=0
  echo NO_CROSS_SHA_PASS_INHERITANCE=1
  echo ---STATUS---
  type "%STATUS%"
) > "%MASTER%"
exit /b 0
