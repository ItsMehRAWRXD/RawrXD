@echo off
setlocal enabledelayedexpansion

echo ==================================================================
echo   RawrXD Full Stack Launch - Bridge Mode
echo   Complete LLM Inference Pipeline
echo ==================================================================
echo.

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: Configuration
set "MODEL_PATH=F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf"
set "MAX_TOKENS=100"
set "HTTP_PORT=8080"

:: Check if model path is provided as argument
if "%~1" neq "" set "MODEL_PATH=%~1"

echo [Config] Model: %MODEL_PATH%
echo [Config] Max Tokens: %MAX_TOKENS%
echo [Config] HTTP Port: %HTTP_PORT%
echo.

:: Step 1: Start MASM Orchestrator (IPC layer)
echo [1/3] Starting MASM Orchestrator (IPC layer)...
start "RawrXD Orchestrator" cmd /k "echo [Orchestrator] Starting... && SovereignOrchestrator_Fixed.exe ^"%MODEL_PATH%^" && pause"
timeout /t 3 /nobreak >nul

:: Step 2: Start C++ Inference Engine in Bridge Mode
echo [2/3] Starting C++ Inference Engine (bridge mode)...
start "RawrXD Engine (Bridge)" cmd /k "echo [Bridge] Connecting to orchestrator... && sovereign_super_node.exe --bridge --model ^"%MODEL_PATH%^" --max-tokens %MAX_TOKENS% && pause"
timeout /t 10 /nobreak >nul

:: Step 3: Start HTTP Server
echo [3/3] Starting HTTP Server...
start "RawrXD HTTP Server" cmd /k "echo [HTTP] Starting server on port %HTTP_PORT%... && rawrxd_server.exe --port %HTTP_PORT% --model codestral-22b && pause"
timeout /t 2 /nobreak >nul

echo.
echo ==================================================================
echo   RawrXD is LIVE! All components running.
echo ==================================================================
echo.
echo Health Check:    http://localhost:%HTTP_PORT%/health
echo List Models:     http://localhost:%HTTP_PORT%/v1/models
echo Completions:     http://localhost:%HTTP_PORT%/v1/completions
echo Chat:            http://localhost:%HTTP_PORT%/v1/chat/completions
echo.
echo Editor Configuration:
echo   VS Code + Continue.dev: Set API URL to http://localhost:%HTTP_PORT%/v1
echo   Cursor: Set custom OpenAI endpoint to http://localhost:%HTTP_PORT%
echo   Neovim: Configure CodeCompanion with url = "http://localhost:%HTTP_PORT%"
echo.
echo Press any key to stop all components...
pause >nul

:: Cleanup - kill all RawrXD processes
echo.
echo [Cleanup] Stopping all RawrXD components...
taskkill /FI "WINDOWTITLE:RawrXD Orchestrator" /F >nul 2>&1
taskkill /FI "WINDOWTITLE:RawrXD Engine (Bridge)" /F >nul 2>&1
taskkill /FI "WINDOWTITLE:RawrXD HTTP Server" /F >nul 2>&1
taskkill /IM SovereignOrchestrator_Fixed.exe /F >nul 2>&1
taskkill /IM sovereign_super_node.exe /F >nul 2>&1
taskkill /IM rawrxd_server.exe /F >nul 2>&1
echo [Cleanup] Done!
echo.
pause
