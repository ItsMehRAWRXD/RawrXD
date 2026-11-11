@echo off
echo ==================================================================
echo   RawrXD Bridge Mode Test
echo ==================================================================
echo.

:: Test 1: Check if orchestrator is running
echo [Test 1] Checking if orchestrator shared memory exists...
handle SOVEREIGN_BEACON_V1 >nul 2>&1
if %errorlevel% equ 0 (
    echo [Test 1] PASS - Shared memory exists
) else (
    echo [Test 1] FAIL - Shared memory not found
    echo          Please start SovereignOrchestrator_Fixed.exe first
    exit /b 1
)

echo.
echo [Test 2] Starting bridge mode...
echo          This will connect to the orchestrator and wait for commands.
echo          Press Ctrl+C to exit after testing.
echo.

:: Run bridge mode with a small model for testing
sovereign_super_node.exe --bridge --model "F:\OllamaModels\phi3-mini-Q2_K.gguf" --max-tokens 50

echo.
echo [Test Complete]
pause
