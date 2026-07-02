@echo off
echo === RawrXD Server Launch ===

echo [1/2] Starting SovereignOrchestrator...
start "RawrXD Orchestrator" cmd /k "SovereignOrchestrator_Fixed.exe"

echo Waiting for engine to initialize...
timeout /t 5 /nobreak >nul

echo [2/2] Starting OpenAI-compatible server...
start "RawrXD Server" cmd /k "rawrxd_server.exe --port 8080 --model codestral-22b"

echo.
echo === RawrXD is ready! ===
echo Connect your editor to: http://localhost:8080/v1
echo.
pause
