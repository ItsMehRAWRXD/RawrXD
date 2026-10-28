@echo off
setlocal EnableExtensions
set EVID=%~dp0
cd /d "%EVID%"
call "%EVID%_build_runtime_hmac.bat"
if errorlevel 1 exit /b 1
echo ---- RUN ----
"%EVID%runtime_hmac_product_smoke.exe" > "%EVID%RUNTIME_run.log" 2>&1
set RC=%ERRORLEVEL%
type "%EVID%RUNTIME_run.log"
echo ----
echo SMOKE_EXIT=%RC%
copy /Y "%EVID%RUNTIME_run.log" "%EVID%RUNTIME_HMAC_PRODUCT_smoke_run.log" >nul
exit /b %RC%
