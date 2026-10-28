@echo off
setlocal EnableExtensions
set EVID=%~dp0
cd /d "%EVID%"
call "%EVID%_build_runtime_auth_e2e.bat"
if errorlevel 1 exit /b 1
echo ---- RUN ----
"%EVID%runtime_auth_e2e_smoke.exe" > "%EVID%RUNTIME_E2E_run.log" 2>&1
set RC=%ERRORLEVEL%
type "%EVID%RUNTIME_E2E_run.log"
echo ----
echo SMOKE_EXIT=%RC%
copy /Y "%EVID%RUNTIME_E2E_run.log" "%EVID%RUNTIME_E2E_smoke_run.log" >nul
exit /b %RC%
