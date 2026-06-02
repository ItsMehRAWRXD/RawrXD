@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo RawrXD API Shadow Mode Test
echo ==========================================

set API_URL=http://localhost:11434/v1/chat/completions
set BALANCER_URL=http://localhost:12639/

echo.
echo [1] Testing Mock Balancer on port 12639...
curl -s -o nul -w "%%{http_code}" %BALANCER_URL%
if %errorlevel%==0 (
    echo     Mock Balancer: OK
) else (
    echo     Mock Balancer: NOT RESPONDING
)

echo.
echo [2] Testing API Server on port 11434...
curl -s -X POST %API_URL% -H "Content-Type: application/json" -d "{\"model\":\"test\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}" -w "\nHTTP Code: %%{http_code}\n" -o response.json
if exist response.json (
    type response.json
    del response.json
)

echo.
echo [3] Checking for log files...
if exist "D:\rawrxd\api_shadow_smoke.log" (
    echo     Found: api_shadow_smoke.log
    echo     First 10 lines:
    head -10 "D:\rawrxd\api_shadow_smoke.log"
) else (
    echo     Log file not found
)

echo.
echo ==========================================
echo Test Complete
echo ==========================================
pause
