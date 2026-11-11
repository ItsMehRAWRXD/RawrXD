@echo off
REM Sovereign Engine Quick Deploy - Run from Head Node (192.168.1.10)
REM This script executes the full deployment sequence

echo ========================================
echo Sovereign Engine Deployment
echo Target: 192.168.1.10-17
echo ========================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Please run as Administrator
    pause
    exit /b 1
)

REM Validate cluster
echo [1/5] Validating cluster connectivity...
powershell -ExecutionPolicy Bypass -File deploy_staging_cluster_fixed.ps1 -ValidateOnly
if %errorLevel% neq 0 (
    echo ERROR: Cluster validation failed
    pause
    exit /b 1
)

REM Deploy binaries
echo.
echo [2/5] Deploying binaries to all nodes...
powershell -ExecutionPolicy Bypass -File deploy_staging_cluster_fixed.ps1
if %errorLevel% neq 0 (
    echo ERROR: Deployment failed
    pause
    exit /b 1
)

REM Start swarm
echo.
echo [3/5] Starting swarm...
powershell -ExecutionPolicy Bypass -File start_swarm.ps1
if %errorLevel% neq 0 (
    echo ERROR: Failed to start swarm
    pause
    exit /b 1
)

REM Wait for stabilization
echo.
echo [4/5] Waiting for cluster stabilization (30 seconds)...
timeout /t 30 /nobreak >nul

REM Run integration test
echo.
echo [5/5] Running integration validation...
powershell -ExecutionPolicy Bypass -File integration_test_full.ps1 -Verbose

echo.
echo ========================================
echo Deployment Complete!
echo ========================================
echo.
echo To monitor: .\monitor_cluster.ps1 -Continuous
echo To stop:    .\stop_swarm.ps1
echo.
pause
