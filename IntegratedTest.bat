@echo off
cd /d D:\rawrxd-ci-bootstrap

echo ========================================
echo   RAWRXD INTEGRATED TEST
echo ========================================
echo.

:: Kill existing
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
timeout /t 2 > nul

echo [1/3] Starting Orchestrator...
echo.

:: Start orchestrator in background
start /B cmd /c "SovereignOrchestrator.exe ""F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf"" > orch_output.txt 2>&1"

echo [2/3] Waiting for initialization (15 seconds)...
timeout /t 15 > nul

echo [3/3] Running Chat Client...
echo.

:: Run chat client
SovereignChatClient.exe

echo.
echo ========================================
echo   ORCHESTRATOR OUTPUT
echo ========================================
type orch_output.txt

echo.
echo ========================================
echo   CLEANUP
echo ========================================
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
echo Done.
pause
