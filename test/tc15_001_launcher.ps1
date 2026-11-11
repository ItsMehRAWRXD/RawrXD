# =============================================================================
# TC15_001 Environment Setup and Launcher
# Phase 15: IDE Integration Test Execution
# =============================================================================

# Set environment variables for debug verbose mode
${env:SOVEREIGN_TELEMETRY_ENABLED} = "1"
${env:SOVEREIGN_TELEMETRY_LEVEL} = "DEBUG"
${env:SOVEREIGN_TELEMETRY_PATH} = "D:\RawrXD\logs\telemetry.log"
${env:SOVEREIGN_IPC_VERBOSE} = "1"
${env:SOVEREIGN_MMAP_PREFETCH} = "1"
${env:SOVEREIGN_KV_CACHE_Q4K} = "1"

Write-Host "=== TC15_001 Environment Configuration ===" -ForegroundColor Green
Write-Host ""
Write-Host "Telemetry:"
Write-Host "  SOVEREIGN_TELEMETRY_ENABLED = ${env:SOVEREIGN_TELEMETRY_ENABLED}"
Write-Host "  SOVEREIGN_TELEMETRY_LEVEL = ${env:SOVEREIGN_TELEMETRY_LEVEL}"
Write-Host "  SOVEREIGN_TELEMETRY_PATH = ${env:SOVEREIGN_TELEMETRY_PATH}"
Write-Host ""
Write-Host "IPC Bridge:"
Write-Host "  SOVEREIGN_IPC_VERBOSE = ${env:SOVEREIGN_IPC_VERBOSE}"
Write-Host ""
Write-Host "Engine:"
Write-Host "  SOVEREIGN_MMAP_PREFETCH = ${env:SOVEREIGN_MMAP_PREFETCH}"
Write-Host "  SOVEREIGN_KV_CACHE_Q4K = ${env:SOVEREIGN_KV_CACHE_Q4K}"
Write-Host ""

# Create logs directory
$logDir = "D:\RawrXD\logs"
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    Write-Host "Created logs directory: $logDir" -ForegroundColor Green
}

# Clear previous logs
$telemetryLog = "$logDir\telemetry.log"
if (Test-Path $telemetryLog) {
    Remove-Item $telemetryLog -Force
    Write-Host "Cleared previous telemetry log" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Environment ready for TC15_001 execution." -ForegroundColor Green
Write-Host ""

# Menu
Write-Host "Select execution mode:" -ForegroundColor Cyan
Write-Host "  1. Dry Run (connectivity check only)"
Write-Host "  2. Live Test (10 iterations)"
Write-Host "  3. Live Test (100 iterations - full validation)"
Write-Host "  4. Exit"
Write-Host ""

$choice = Read-Host "Enter choice (1-4)"

switch ($choice) {
    "1" {
        Write-Host "`n=== Running Dry Run ===" -ForegroundColor Yellow
        & "$PSScriptRoot\tc15_001_runner.ps1" -DryRun -Verbose
    }
    "2" {
        Write-Host "`n=== Running Live Test (10 iterations) ===" -ForegroundColor Yellow
        & "$PSScriptRoot\tc15_001_runner.ps1" -Iterations 10 -Verbose
    }
    "3" {
        Write-Host "`n=== Running Live Test (100 iterations) ===" -ForegroundColor Yellow
        & "$PSScriptRoot\tc15_001_runner.ps1" -Iterations 100 -Verbose
    }
    "4" {
        Write-Host "Exiting..." -ForegroundColor Gray
        exit 0
    }
    default {
        Write-Host "Invalid choice. Exiting." -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n=== TC15_001 Execution Complete ===" -ForegroundColor Green
Write-Host "Review logs at: $telemetryLog" -ForegroundColor Cyan
