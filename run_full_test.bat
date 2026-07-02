@echo off
cd /d D:\rawrxd-ci-bootstrap

echo ========================================
echo   RAWRXD FULL INTEGRATION TEST
echo ========================================
echo.

:: Kill any existing orchestrator
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1
timeout /t 2 > nul

echo [1/4] Starting SovereignOrchestrator...
echo       Model: Codestral-22B-v0.1-Q4_K_M.gguf
echo.
start /B SovereignOrchestrator.exe "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf" > orch_log.txt 2>&1

echo [2/4] Waiting for initialization (20 seconds)...
timeout /t 20 > nul

echo [3/4] Running Full Integration Test...
echo.
FullIntegrationTest.exe

echo.
echo [4/4] Cleanup...
taskkill /F /IM SovereignOrchestrator.exe > nul 2>&1

echo.
echo ========================================
echo   ORCHESTRATOR LOG
echo ========================================
type orch_log.txt

echo.
echo ========================================
echo   TEST COMPLETE
echo ========================================
