@echo off
cd /d D:\rawrxd-ci-bootstrap

echo ========================================
echo   RAWRXD FINAL INTEGRATION TEST
echo ========================================
echo.

:: Kill existing orchestrator
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
timeout /t 2 > nul

echo [1/5] Starting orchestrator...
start /B SovereignOrchestrator.exe > orch_output.txt 2>&1
timeout /t 3 > nul

echo [2/5] Loading model via SDK...
echo Model path: F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf
echo.
echo Note: Model must be loaded via CMD_LOAD_MODEL command
echo before inference can work. The orchestrator starts in
echo MODEL_STATE_UNLOADED state.
echo.

echo [3/5] Running chat client (will attempt inference)...
echo.
SovereignChatClient.exe
echo.

echo [4/5] Test complete!
echo.

echo [5/5] Cleanup...
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
echo Done.
echo.
echo ========================================
echo   ORCHESTRATOR OUTPUT
echo ========================================
type orch_output.txt
