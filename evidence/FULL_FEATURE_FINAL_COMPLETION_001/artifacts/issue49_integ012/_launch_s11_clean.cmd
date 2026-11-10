@echo off
setlocal
REM Clean exclusive S11 launch. No WMI. PROMOTE=0.
taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
taskkill /F /IM llama-server.exe >nul 2>&1
taskkill /F /IM debuggee_fixture.exe >nul 2>&1
del /f /q "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock" >nul 2>&1
timeout /t 3 /nobreak >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\_run_s11_agent_owned_exclusive.ps1" -WaitSec 600 > "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\_run_s11_agent_owned_exclusive.console.txt" 2>&1
echo HARNESS_EC=%ERRORLEVEL%>> "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\_run_s11_agent_owned_exclusive.console.txt"
exit /b %ERRORLEVEL%
