# RawrZ Security Platform - Privileged Deployment Script (PowerShell)
# This script deploys the application with elevated privileges

param(
    [switch]$Force
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrZ Security Platform - Privileged Deploy" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "[ERROR] This script requires Administrator privileges" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please run PowerShell as Administrator and try again:" -ForegroundColor Yellow
    Write-Host "1. Right-click on PowerShell" -ForegroundColor White
    Write-Host "2. Select 'Run as administrator'" -ForegroundColor White
    Write-Host "3. Navigate to this directory" -ForegroundColor White
    Write-Host "4. Run: .\deploy-privileged.ps1" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green
Write-Host ""

# Check if Docker is running
try {
    docker version | Out-Null
    Write-Host "[OK] Docker is running" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker is not running or not installed" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Stop any existing containers
Write-Host "[INFO] Stopping existing containers..." -ForegroundColor Yellow
try {
    docker-compose -f docker-compose.privileged.yml down 2>$null
} catch {
    Write-Host "[INFO] No existing containers to stop" -ForegroundColor Yellow
}

# Remove old images
Write-Host "[INFO] Cleaning up old images..." -ForegroundColor Yellow
docker image prune -f

# Build and start with privileged access
Write-Host "[INFO] Building privileged container..." -ForegroundColor Yellow
docker-compose -f docker-compose.privileged.yml build --no-cache

Write-Host "[INFO] Starting privileged container..." -ForegroundColor Yellow
docker-compose -f docker-compose.privileged.yml up -d

# Wait for container to be ready
Write-Host "[INFO] Waiting for container to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check container status
$containerStatus = docker-compose -f docker-compose.privileged.yml ps
if ($containerStatus -match "Up") {
    Write-Host "[OK] Container is running with privileged access" -ForegroundColor Green
    Write-Host ""
    Write-Host "RawrZ Security Platform is now running with full privileges:" -ForegroundColor Cyan
    Write-Host "  - Main Panel: http://localhost:3000" -ForegroundColor White
    Write-Host "  - API Endpoint: http://localhost:3000/api/rawrz-engine/status" -ForegroundColor White
    Write-Host "  - Health Check: http://localhost:3000/health" -ForegroundColor White
    Write-Host ""
    Write-Host "All engines now have full system access:" -ForegroundColor Green
    Write-Host "  - Red Killer: Full registry and service control" -ForegroundColor White
    Write-Host "  - Private Virus Scanner: Complete system scanning" -ForegroundColor White
    Write-Host "  - AI Threat Detector: Full model training and saving" -ForegroundColor White
    Write-Host "  - All other engines: Maximum functionality" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "[ERROR] Container failed to start" -ForegroundColor Red
    Write-Host ""
    Write-Host "Checking logs..." -ForegroundColor Yellow
    docker-compose -f docker-compose.privileged.yml logs
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[INFO] Deployment completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "To view logs: docker-compose -f docker-compose.privileged.yml logs -f" -ForegroundColor Cyan
Write-Host "To stop: docker-compose -f docker-compose.privileged.yml down" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
