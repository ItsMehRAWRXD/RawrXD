@echo off
setlocal
REM Four-panel probe on tip_final_005 (7123…). Scenarios measured independently; no invent PASS.
set LANE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001
set EXE=%LANE%\candidates\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
set OUT=%LANE%\artifacts\four_panel_probe_7123.txt
set STATUS=%LANE%\artifacts\four_panel_status_7123.txt
echo START %DATE% %TIME%> "%STATUS%"
if not exist "%EXE%" (
  echo EXE_MISSING>> "%STATUS%"
  exit /b 1
)
certutil -hashfile "%EXE%" SHA256 > "%LANE%\artifacts\four_panel_sha_7123.txt"
echo S1_TERM_SMOKE_BEGIN>> "%STATUS%"
del /Q "%LANE%\artifacts\term_smoke_receipt.txt" 2>nul
"%EXE%" --term-smoke --term-quit
echo S1_TERM_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\term_smoke_receipt.txt" (
  findstr /C:CONPTY=PASS "%LANE%\artifacts\term_smoke_receipt.txt" >nul && echo S1_TERMINAL=PASS>> "%STATUS%" || echo S1_TERMINAL=FAIL>> "%STATUS%"
) else (
  echo S1_TERMINAL=FAIL_NO_RECEIPT>> "%STATUS%"
)
echo S2_EXT_BEGIN>> "%STATUS%"
del /Q "%LANE%\artifacts\ext_runtime_receipt.txt" 2>nul
"%EXE%" --ext-dir "%LANE%\fixtures\ext_hello" --ext-cmd extHello.ping --ext-quit
echo S2_EXT_EXIT=%ERRORLEVEL%>> "%STATUS%"
if exist "%LANE%\artifacts\ext_runtime_receipt.txt" (
  findstr /C:ACTIVATE_OK=1 "%LANE%\artifacts\ext_runtime_receipt.txt" >nul && echo S2_EXT=PASS>> "%STATUS%" || echo S2_EXT=FAIL>> "%STATUS%"
) else (
  echo S2_EXT=FAIL_NO_RECEIPT>> "%STATUS%"
)
echo S3_DEBUG_BACKEND=SEE_DEBUG_CONSOLE_GATE tip_debug_001 SEPARATE_SHA>> "%STATUS%"
echo S4_OUTPUT_PROBLEMS=SEE_IDE_PANELS_GUI_RECEIPT tip_633AB013 SEPARATE_SHA>> "%STATUS%"
echo S5_FOUR_PANEL_COMBINED_1_17=NOT_RUN>> "%STATUS%"
echo DONE>> "%STATUS%"
type "%STATUS%" > "%OUT%"
exit /b 0
