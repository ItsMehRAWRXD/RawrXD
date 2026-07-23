@echo off
setlocal EnableDelayedExpansion

echo RawrXD Endpoint Validator
echo ==========================
echo.
echo Testing endpoints in batches of 20...
echo.

set "BASE_URL=http://localhost:9090"
set "PASS_COUNT=0"
set "FAIL_COUNT=0"

REM Test endpoints
call :test_endpoint GET /api/status
call :test_endpoint GET /api/tags
call :test_endpoint GET /api/full-state
call :test_endpoint GET /api/memory/stats
call :test_endpoint GET /api/memory/status
call :test_endpoint GET /api/ws-stats
call :test_endpoint GET /api/cot/health
call :test_endpoint GET /api/cot/metrics
call :test_endpoint GET /api/agents
call :test_endpoint GET /api/agents/status
call :test_endpoint GET /api/agents/history
call :test_endpoint GET /api/policies
call :test_endpoint GET /api/policies/suggestions
call :test_endpoint GET /api/policies/stats
call :test_endpoint GET /api/policies/heuristics
call :test_endpoint GET /api/backends
call :test_endpoint GET /api/backends/status
call :test_endpoint GET /api/agentic/config
call :test_endpoint GET /api/gpu/status
call :test_endpoint GET /api/tuner/status

echo.
echo ==========================
echo Batch 1 Complete
echo ==========================
echo.

REM Continue with more endpoints...
call :test_endpoint POST /api/generate
call :test_endpoint POST /v1/chat/completions
call :test_endpoint POST /api/chat
call :test_endpoint POST /api/complete
call :test_endpoint POST /api/complete/stream
call :test_endpoint POST /api/pull
call :test_endpoint POST /api/command
call :test_endpoint POST /api/cot
call :test_endpoint POST /api/read-file
call :test_endpoint POST /api/reasoning/depth
call :test_endpoint POST /api/reasoning/preset
call :test_endpoint POST /api/agent/bulkfix
call :test_endpoint POST /api/agent/plan
call :test_endpoint POST /api/agents/replay
call :test_endpoint POST /api/policies/apply
call :test_endpoint POST /api/policies/reject
call :test_endpoint POST /api/policies/import
call :test_endpoint POST /api/backends/use
call :test_endpoint POST /api/agentic/config
call :test_endpoint POST /api/gpu/toggle

echo.
echo ==========================
echo Batch 2 Complete
echo ==========================
echo.

echo.
echo Final Results:
echo   Passed: %PASS_COUNT%
echo   Failed: %FAIL_COUNT%
echo.

if %FAIL_COUNT%==0 (
    echo ALL ENDPOINTS PASSED!
) else (
    echo SOME ENDPOINTS FAILED
)

goto :eof

:test_endpoint
set "METHOD=%~1"
set "PATH=%~2"
set /a "TOTAL+=1"

echo Testing [%METHOD%] %PATH% ... 

curl -s -o nul -w "%%{http_code}" -X %METHOD% "%BASE_URL%%PATH%" > temp_status.txt 2>nul
set /p STATUS=<temp_status.txt

if "%METHOD%"=="POST" (
    curl -s -o nul -w "%%{http_code}" -X POST -H "Content-Type: application/json" -d "{}" "%BASE_URL%%PATH%" > temp_status.txt 2>nul
    set /p STATUS=<temp_status.txt
)

if %STATUS%==200 (
    echo PASS (HTTP %STATUS%)
    set /a "PASS_COUNT+=1"
) else (
    if %STATUS%==426 (
        echo PASS (HTTP %STATUS% - Expected for WebSocket)
        set /a "PASS_COUNT+=1"
    ) else (
        echo FAIL (HTTP %STATUS%)
        set /a "FAIL_COUNT+=1"
    )
)

del temp_status.txt 2>nul
goto :eof
