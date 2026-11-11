@echo off
taskkill /F /IM llama-cli.exe >nul 2>&1
taskkill /F /IM llama-cli-impl.dll >nul 2>&1
rem kill the build_and_run powershell by window title not reliable; kill by pid files
for /f "tokens=2" %%a in ('tasklist /FI "IMAGENAME eq powershell.exe" /FO LIST ^| findstr /I PID') do (
  echo PS_PID=%%a
)
taskkill /F /PID 3284 >nul 2>&1
taskkill /F /PID 30868 >nul 2>&1
taskkill /F /PID 14240 >nul 2>&1
echo KILL_DONE
