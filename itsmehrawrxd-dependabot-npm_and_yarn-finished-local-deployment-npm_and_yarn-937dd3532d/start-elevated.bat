@echo off
echo ========================================
echo RawrZ Security Platform - Elevated Mode
echo ========================================
echo.
echo Starting with Administrator privileges...
echo This will enable full functionality for all engines.
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
    echo.
    echo Starting RawrZ Security Platform...
    echo.
    
    REM Change to the script directory
    cd /d "%~dp0"
    
    REM Kill any existing Node.js processes
    taskkill /F /IM node.exe 2>nul
    
    REM Start the server with elevated privileges
    node api-server.js
    
) else (
    echo [ERROR] This script requires Administrator privileges
    echo.
    echo Please run this script as Administrator:
    echo 1. Right-click on start-elevated.bat
    echo 2. Select "Run as administrator"
    echo 3. Click "Yes" when prompted by UAC
    echo.
    echo Alternatively, you can:
    echo 1. Open Command Prompt as Administrator
    echo 2. Navigate to this directory
    echo 3. Run: start-elevated.bat
    echo.
    pause
    exit /b 1
)

echo.
echo RawrZ Security Platform has stopped.
pause
