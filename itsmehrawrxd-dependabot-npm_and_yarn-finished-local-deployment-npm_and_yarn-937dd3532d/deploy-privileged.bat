@echo off
REM RawrZ Security Platform - Privileged Deployment (Batch)
REM Simple batch file to deploy with elevated privileges - no admin required!

echo.
echo ========================================
echo RawrZ Security Platform - Privileged Deploy
echo ========================================
echo.

REM Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] PowerShell is not available
    echo Please install PowerShell and try again
    pause
    exit /b 1
)

echo [INFO] Starting privileged deployment...
echo [INFO] No administrator privileges required!
echo.

REM Run the PowerShell deployment script
powershell -ExecutionPolicy Bypass -File "deploy-digitalocean-privileged.ps1"

echo.
echo [INFO] Deployment completed!
echo.
pause
