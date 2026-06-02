@echo off
set RAWRXD_API_LOG_FILE=D:\rawrxd\api_shadow_smoke.log
set RAWRXD_BALANCER_SHADOW_MODE=true
set RAWRXD_BALANCER_PORT=11434
echo [LAUNCHER] RAWRXD_API_LOG_FILE=%RAWRXD_API_LOG_FILE%
echo [LAUNCHER] Starting RawrXD-Win32IDE.exe...
start "" "d:\rxdn_ninja\bin\RawrXD-Win32IDE.exe"
echo [LAUNCHER] Process started. Waiting 5 seconds for initialization...
timeout /t 5 /nobreak >nul
echo [LAUNCHER] Ready for smoke test.
