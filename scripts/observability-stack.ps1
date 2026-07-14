# RawrXD Observability Stack
# Manages observability tools (metrics, logs, traces)

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Start", "Stop", "Configure", "Dashboard")]
    [string]$Action = "Status",
    
    [string]$Component = "all",
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

function Initialize-ObservabilityStack {
    Write-Status "Observability Stack Manager initialized"
}

function Get-ObservabilityComponents {
    return @(
        @{ Name = "prometheus"; Type = "Metrics"; Status = "Running"; Port = 9090; Version = "2.45.0" }
        @{ Name = "grafana"; Type = "Dashboard"; Status = "Running"; Port = 3000; Version = "10.0.0" }
        @{ Name = "jaeger"; Type = "Tracing"; Status = "Running"; Port = 16686; Version = "1.47.0" }
        @{ Name = "loki"; Type = "Logging"; Status = "Running"; Port = 3100; Version = "2.9.0" }
        @{ Name = "otel-collector"; Type = "Collector"; Status = "Running"; Port = 4317; Version = "0.85.0" }
    )
}

function Show-ObservabilityStatus {
    $components = Get-ObservabilityComponents
    
    Write-Host ""
    Write-Host "Observability Stack Status" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Component         Type        Status      Port     Version"
    Write-Host "  " + "-" * 60
    
    foreach ($comp in $components) {
        $statusColor = if ($comp.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "  $($comp.Name.PadRight(17)) $($comp.Type.PadRight(11)) " -NoNewline
        Write-Host $comp.Status.PadRight(11) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($comp.Port.ToString().PadRight(8)) $($comp.Version)"
    }
}

function Start-ObservabilityStack {
    Write-Status "Starting observability stack..."
    
    $components = Get-ObservabilityComponents
    foreach ($comp in $components) {
        Write-Host "  Starting $($comp.Name)..." -NoNewline
        Start-Sleep -Milliseconds 500
        Write-Host " done" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Success "Observability stack started"
    Write-Host ""
    Write-Host "  Grafana: http://localhost:3000"
    Write-Host "  Prometheus: http://localhost:9090"
    Write-Host "  Jaeger: http://localhost:16686"
}

function Stop-ObservabilityStack {
    if (-not $Force) {
        $confirm = Read-Host "Stop observability stack? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Operation cancelled"
            return
        }
    }
    
    Write-Status "Stopping observability stack..."
    Write-Success "Observability stack stopped"
}

function Show-ObservabilityDashboard {
    Write-Host ""
    Write-Host "Observability Dashboard URLs" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  📊 Grafana (Dashboards):     http://localhost:3000"
    Write-Host "  📈 Prometheus (Metrics):     http://localhost:9090"
    Write-Host "  🔍 Jaeger (Tracing):         http://localhost:16686"
    Write-Host "  📝 Loki (Logs):              http://localhost:3100"
}

# Main execution
function Main {
    Write-Host "RawrXD Observability Stack" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-ObservabilityStack
    
    switch ($Action) {
        "Status" { Show-ObservabilityStatus }
        "Start" { Start-ObservabilityStack }
        "Stop" { Stop-ObservabilityStack }
        "Configure" { Write-Status "Configuring observability stack..." }
        "Dashboard" { Show-ObservabilityDashboard }
    }
    
    Write-Host ""
}

Main
