@echo off
echo ==========================================
echo Testing RawrXD + Throttle Proxy
echo ==========================================
echo.

REM Check if RawrXD is running
echo [1/3] Checking RawrXD on port 9090...
curl -s http://127.0.0.1:9090/api/status > nul 2>&1
if %errorlevel% neq 0 (
    echo      RawrXD not running. Starting it...
    start "" "d:\rawrxd\bin\RawrXD-Win32IDE.exe"
    timeout /t 5 > nul
) else (
    echo      RawrXD is running!
)

REM Check if Proxy is running
echo.
echo [2/3] Checking Throttle Proxy on port 9091...
curl -s http://127.0.0.1:9091/api/model/profiles > nul 2>&1
if %errorlevel% neq 0 (
    echo      Proxy not running. Starting it...
    cd /d "d:\rawrxd\extensions\copilot-throttle"
    start "" node proxy-server-fixed.js
    timeout /t 3 > nul
) else (
    echo      Proxy is running!
)

REM Test the endpoints
echo.
echo [3/3] Testing endpoints...
echo.
echo Testing /api/model/profiles:
curl -s http://127.0.0.1:9091/api/model/profiles | findstr "profiles"
if %errorlevel% equ 0 (
    echo      [OK] /api/model/profiles works!
) else (
    echo      [FAIL] /api/model/profiles not responding
)

echo.
echo Testing /api/engine/capabilities:
curl -s http://127.0.0.1:9091/api/engine/capabilities | findstr "bridge"
if %errorlevel% equ 0 (
    echo      [OK] /api/engine/capabilities works!
) else (
    echo      [FAIL] /api/engine/capabilities not responding
)

echo.
echo ==========================================
echo Test Complete!
echo ==========================================
echo.
echo You can now use the HTML IDE with:
echo   - RawrXD: http://127.0.0.1:9090
echo   - Proxy:  http://127.0.0.1:9091
echo.
pause
