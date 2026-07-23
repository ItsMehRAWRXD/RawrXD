@echo off
echo ==========================================
echo RawrXD + Copilot Throttle Launcher
echo ==========================================
echo.

REM Start RawrXD
echo [1/2] Starting RawrXD...
start "" "d:\rawrxd\bin\RawrXD-Win32IDE.exe"
echo      Waiting 5 seconds for initialization...
timeout /t 5 /nobreak > nul
echo      RawrXD started!
echo.

REM Start Proxy
echo [2/2] Starting Throttle Proxy...
cd /d "d:\rawrxd\extensions\copilot-throttle"
start "" node proxy-server-fixed.js
echo      Waiting 3 seconds for initialization...
timeout /t 3 /nobreak > nul
echo      Proxy started!
echo.

echo ==========================================
echo Setup Complete!
echo ==========================================
echo RawrXD:   http://127.0.0.1:9090
echo Throttle: http://127.0.0.1:9091
echo Max Tokens: 2048
echo ==========================================
echo.
echo You can now use Copilot with your local model!
pause
