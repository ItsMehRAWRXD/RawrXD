@echo off
echo Starting RawrXD with Copilot Throttle...
echo.

REM Start RawrXD
echo [1/3] Starting RawrXD on port 9090...
start /B "" "d:\rawrxd\bin\RawrXD-Win32IDE.exe"
timeout /t 3 /nobreak > nul

REM Check if RawrXD is running
curl -s http://127.0.0.1:9090/api/status > nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: RawrXD failed to start on port 9090
    pause
    exit /b 1
)
echo RawrXD is running!
echo.

REM Start Throttle Proxy
echo [2/3] Starting Throttle Proxy on port 9091...
cd /d "d:\rawrxd\extensions\copilot-throttle"
start /B "" node proxy-server.js
timeout /t 2 /nobreak > nul

REM Check if proxy is running
curl -s http://127.0.0.1:9091/api/status > nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Proxy failed to start on port 9091
    pause
    exit /b 1
)
echo Throttle Proxy is running!
echo.

echo [3/3] Configuration complete!
echo.
echo ==========================================
echo RawrXD:     http://127.0.0.1:9090
echo Throttle:   http://127.0.0.1:9091
echo Max Tokens: 2048
echo ==========================================
echo.
echo Your Copilot chat is now configured to use
echo the throttled endpoint. Try chatting now!
echo.
pause
