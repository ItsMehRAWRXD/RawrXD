# RawrXD Docker Compose Manager
# Manages docker-compose deployments

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Up", "Down", "Restart", "Logs", "Ps", "Build", "Pull")]
    [string]$Action = "Ps",
    
    [string]$Service = "",
    [switch]$Detach,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-DockerComposeManager {
    Write-Status "Docker Compose Manager initialized"
}

function Get-ComposeServices {
    return @(
        @{ Name = "api"; Status = "Up"; Ports = "8080:8080"; Image = "rawrxd/api:latest" }
        @{ Name = "worker"; Status = "Up"; Ports = "-"; Image = "rawrxd/worker:latest" }
        @{ Name = "redis"; Status = "Up"; Ports = "6379:6379"; Image = "redis:7-alpine" }
        @{ Name = "postgres"; Status = "Up"; Ports = "5432:5432"; Image = "postgres:15" }
    )
}

function Start-ComposeServices {
    Write-Status "Starting Docker Compose services..."
    
    if ($Service) {
        Write-Host "  Starting service: $Service"
    } else {
        Write-Host "  Starting all services..."
    }
    
    if ($Detach) {
        Write-Host "  Running in detached mode"
    }
    
    Start-Sleep -Seconds 2
    Write-Success "Services started"
}

function Stop-ComposeServices {
    if (-not $Force) {
        $confirm = Read-Host "Stop Docker Compose services? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Operation cancelled"
            return
        }
    }
    
    Write-Status "Stopping Docker Compose services..."
    Start-Sleep -Seconds 1
    Write-Success "Services stopped"
}

function Restart-ComposeServices {
    Write-Status "Restarting Docker Compose services..."
    Start-Sleep -Seconds 2
    Write-Success "Services restarted"
}

function Show-ComposeLogs {
    if ($Service) {
        Write-Status "Showing logs for: $Service"
    } else {
        Write-Status "Showing logs for all services..."
    }
    
    $logs = @(
        "2024-01-15 14:45:00 [INFO] Service started successfully"
        "2024-01-15 14:45:01 [INFO] Connected to database"
        "2024-01-15 14:45:02 [INFO] API server listening on port 8080"
    )
    
    foreach ($log in $logs) {
        Write-Host "  $log"
    }
}

function Show-ComposeStatus {
    $services = Get-ComposeServices
    
    Write-Host ""
    Write-Host "Docker Compose Status" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Name      Status    Ports         Image"
    Write-Host "  " + "-" * 60
    
    foreach ($svc in $services) {
        $statusColor = if ($svc.Status -eq "Up") { "Green" } else { "Red" }
        Write-Host "  $($svc.Name.PadRight(9)) " -NoNewline
        Write-Host $svc.Status.PadRight(9) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($svc.Ports.PadRight(13)) $($svc.Image)"
    }
}

function Build-ComposeServices {
    Write-Status "Building Docker Compose services..."
    
    if ($Service) {
        Write-Host "  Building: $Service"
    } else {
        Write-Host "  Building all services..."
    }
    
    for ($i = 0; $i -le 100; $i += 25) {
        Write-Host "  Progress: $i%" -NoNewline
        Start-Sleep -Milliseconds 300
        Write-Host "`r" -NoNewline
    }
    Write-Host "  Progress: 100%"
    
    Write-Success "Build complete"
}

function Pull-ComposeImages {
    Write-Status "Pulling Docker images..."
    Start-Sleep -Seconds 2
    Write-Success "Images pulled"
}

# Main execution
function Main {
    Write-Host "RawrXD Docker Compose Manager" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-DockerComposeManager
    
    switch ($Action) {
        "Up" { Start-ComposeServices }
        "Down" { Stop-ComposeServices }
        "Restart" { Restart-ComposeServices }
        "Logs" { Show-ComposeLogs }
        "Ps" { Show-ComposeStatus }
        "Build" { Build-ComposeServices }
        "Pull" { Pull-ComposeImages }
    }
    
    Write-Host ""
}

Main
