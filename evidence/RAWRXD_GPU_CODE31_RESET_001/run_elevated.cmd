@echo off
:: UAC-elevated Code 31 clear via Deep2 GpuPreflight reset path.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0elev_run.ps1"
echo.
type "%~dp0elev_run.log" 2>nul
echo.
pause
