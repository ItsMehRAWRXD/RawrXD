@echo off
cd /d D:\rawrxd-ci-bootstrap

echo ========================================
echo   RAWRXD END-TO-END TEST (BATCH)
echo ========================================
echo.

:: Kill existing orchestrator
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1

timeout /t 2 > nul

echo [1/3] Starting orchestrator...
start /B SovereignOrchestrator.exe "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf" > orch_output.txt 2>&1

echo [2/3] Waiting for initialization...
timeout /t 10 > nul

echo [3/3] Running chat client...
echo.
SovereignChatClient.exe

echo.
echo ========================================
echo   ORCHESTRATOR OUTPUT
echo ========================================
echo.
type orch_output.txt

echo.
echo ========================================
echo   CLEANUP
echo ========================================
echo.
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
echo Done.
