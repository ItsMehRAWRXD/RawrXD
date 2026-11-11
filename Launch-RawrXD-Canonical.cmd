@echo off
setlocal
rem This path is the exact Release candidate verified by the daily-driver
rem dock and PowerShell smoke test.  Keep stale build_ide and historical G:
rem binaries out of the production launch path.
set "IDE=%~dp0build_crashfix_verify\bin\RawrXD-Win32IDE-Native.exe"
if not exist "%IDE%" (
  echo Canonical RawrXD IDE was not found: "%IDE%"
  exit /b 2
)
echo Launching canonical RawrXD IDE: "%IDE%"
start "RawrXD IDE (canonical)" /D "%~dp0" "%IDE%" %*
exit /b 0
