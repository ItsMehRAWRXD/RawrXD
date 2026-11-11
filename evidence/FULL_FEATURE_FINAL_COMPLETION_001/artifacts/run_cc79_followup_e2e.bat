@echo off
setlocal
echo ==== CC79 FOLLOWUP E2E START %DATE% %TIME% ====
taskkill /F /IM rg.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native.exe >nul 2>&1
taskkill /F /IM debuggee_fixture.exe >nul 2>&1
echo LEFT_RAWRXD before build:
tasklist /FI "IMAGENAME eq RawrXD*" 2>nul
call "%~dp0build_tip_final_integ_003.bat"
set BR=%ERRORLEVEL%
echo BUILD_RC=%BR%
if not "%BR%"=="0" (
  echo BUILD_FAILED
  exit /b %BR%
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0cc79_followup_four_panel_probe.ps1"
set PR=%ERRORLEVEL%
echo PROBE_RC=%PR%
echo ==== CC79 FOLLOWUP E2E END ====
exit /b %PR%
