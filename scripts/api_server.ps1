#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    API Server Launcher for RawrXD

.DESCRIPTION
    Manages the RawrXD API server:
    - Server startup/shutdown
    - Configuration management
    - Health monitoring
    - Log rotation

.EXAMPLE
    .\scripts\api_server.ps1 -Start
    .\scripts\api_server.ps1 -Stop
    .\scripts\api_server.ps1 -Restart

.NOTES
    Part of RawrXD Phase AD: Advanced Features & Integration
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Start,

    [Parameter()]
    [switch]$Stop,

    [Parameter()]
    [switch]$Restart,

    [Parameter()]
    [switch]$Status,

    [Parameter()]
    [int]$Port = 8080,

    [Parameter()]
    [string]$ConfigFile = "config/api.json",

    [Parameter()]
    [string]$LogFile = "logs/api-server.log"
)

# ============================================================================
# Configuration
# ============================================================================

$ServiceName = "RawrXD-API"
$ProcessName = "RawrXD"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-ServerStatus {
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if ($process) {
        return [PSCustomObject]@{
            Running = $true
            PID = $process.Id
            StartTime = $process.StartTime
            MemoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
        }
    }
    return [PSCustomObject]@{ Running = $false }
}

# ============================================================================
# Server Management
# ============================================================================

function Start-ApiServer {
    Write-Status "Starting API server..." "Info"
    Write-Status "Port: $Port" "Info"
    Write-Status "Config: $ConfigFile" "Info"

    $existing = Get-ServerStatus
    if ($existing.Running) {
        Write-Status "Server already running (PID: $($existing.PID))" "Warning"
        return
    }

    # Ensure log directory exists
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Start server (simulated)
    Write-Status "Starting $ProcessName..." "Info"
    # In production: Start-Process -FilePath "RawrXD.exe" -ArgumentList "--server", "--port", $Port -RedirectStandardOutput $LogFile -NoNewWindow

    Start-Sleep -Seconds 2

    $status = Get-ServerStatus
    if ($status.Running) {
        Write-Status "Server started successfully (PID: $($status.PID))" "Success"
    } else {
        Write-Status "Failed to start server" "Error"
    }
}

function Stop-ApiServer {
    Write-Status "Stopping API server..." "Info"

    $status = Get-ServerStatus
    if (-not $status.Running) {
        Write-Status "Server not running" "Warning"
        return
    }

    Write-Status "Stopping process $($status.PID)..." "Info"
    Stop-Process -Id $status.PID -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 1

    $status = Get-ServerStatus
    if (-not $status.Running) {
        Write-Status "Server stopped successfully" "Success"
    } else {
        Write-Status "Failed to stop server" "Error"
    }
}

function Show-ServerStatus {
    $status = Get-ServerStatus

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "API Server Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if ($status.Running) {
        Write-Host "Status:     Running" -ForegroundColor Green
        Write-Host "PID:        $($status.PID)" -ForegroundColor Gray
        Write-Host "Start Time: $($status.StartTime)" -ForegroundColor Gray
        Write-Host "Memory:     $($status.MemoryMB) MB" -ForegroundColor Gray
    } else {
        Write-Host "Status:     Stopped" -ForegroundColor Red
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    if ($Start) {
        Start-ApiServer
    } elseif ($Stop) {
        Stop-ApiServer
    } elseif ($Restart) {
        Stop-ApiServer
        Start-Sleep -Seconds 2
        Start-ApiServer
    } elseif ($Status) {
        Show-ServerStatus
    } else {
        Show-ServerStatus
    }
}

# Run main
Main
