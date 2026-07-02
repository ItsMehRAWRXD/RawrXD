@echo off
cd /d D:\rawrxd-ci-bootstrap

echo ========================================
echo   RAWRXD END-TO-END TEST
echo ========================================
echo.

:: Kill any existing orchestrator
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
timeout /t 2 > nul

echo [1/3] Starting SovereignOrchestrator with Codestral-22B...
start /B SovereignOrchestrator.exe "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf" > orch_log.txt 2>&1

echo [2/3] Waiting for initialization (15 seconds)...
timeout /t 15 > nul

echo [3/3] Running chat client...
echo.
SovereignChatClient.exe

echo.
echo ========================================
echo   ORCHESTRATOR LOG
echo ========================================
type orch_log.txt

echo.
echo ========================================
echo   CLEANUP
echo ========================================
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
echo Done.
