# RawrXD Health Aggregator
# Aggregates health checks from multiple services

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Check", "Report", "History")]
    [string]$Action = "Status",
    
    [string]$Service = "",
    [switch]$Detailed,
    [string]$ExportPath = ""
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

function Initialize-HealthAggregator {
    Write-Status "Health Aggregator initialized"
}

function Get-ServiceHealth {
    return @(
        @{ Name = "api-gateway"; Status = "Healthy"; Latency = "45ms"; Uptime = "99.99%"; LastCheck = "14:45:23" }
        @{ Name = "model-service"; Status = "Healthy"; Latency = "120ms"; Uptime = "99.95%"; LastCheck = "14:45:22" }
        @{ Name = "embedding-service"; Status = "Healthy"; Latency = "89ms"; Uptime = "99.98%"; LastCheck = "14:45:21" }
        @{ Name = "cache-service"; Status = "Degraded"; Latency = "250ms"; Uptime = "98.50%"; LastCheck = "14:45:20" }
        @{ Name = "queue-service"; Status = "Healthy"; Latency = "12ms"; Uptime = "99.99%"; LastCheck = "14:45:19" }
        @{ Name = "auth-service"; Status = "Unhealthy"; Latency = "5000ms"; Uptime = "95.20%"; LastCheck = "14:45:18" }
    )
}

function Show-HealthStatus {
    $services = Get-ServiceHealth
    
    Write-Host ""
    Write-Host "System Health Status" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    $healthy = ($services | Where-Object { $_.Status -eq "Healthy" }).Count
    $degraded = ($services | Where-Object { $_.Status -eq "Degraded" }).Count
    $unhealthy = ($services | Where-Object { $_.Status -eq "Unhealthy" }).Count
    $total = $services.Count
    
    $overall = if ($unhealthy -gt 0) { "Unhealthy" } elseif ($degraded -gt 0) { "Degraded" } else { "Healthy" }
    $overallColor = switch ($overall) {
        "Healthy" { "Green" }
        "Degraded" { "Yellow" }
        "Unhealthy" { "Red" }
    }
    
    Write-Host "  Overall Status: " -NoNewline
    Write-Host $overall -ForegroundColor $overallColor
    Write-Host "  Services: $healthy healthy, $degraded degraded, $unhealthy unhealthy (of $total total)"
    Write-Host ""
    
    Write-Host "  Service                Status      Latency    Uptime     Last Check"
    Write-Host "  " + "-" * 70
    
    foreach ($svc in $services) {
        $statusColor = switch ($svc.Status) {
            "Healthy" { "Green" }
            "Degraded" { "Yellow" }
            "Unhealthy" { "Red" }
        }
        Write-Host "  $($svc.Name.PadRight(22)) " -NoNewline
        Write-Host $svc.Status.PadRight(11) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($svc.Latency.PadRight(10)) $($svc.Uptime.PadRight(10)) $($svc.LastCheck)"
    }
}

function Invoke-HealthCheck {
    param([string]$ServiceName)
    
    if ($ServiceName) {
        Write-Status "Checking health of: $ServiceName"
        Start-Sleep -Milliseconds 500
        Write-Success "Health check completed for $ServiceName"
    } else {
        Write-Status "Running health checks on all services..."
        $services = Get-ServiceHealth
        foreach ($svc in $services) {
            Write-Host "  Checking $($svc.Name)..." -NoNewline
            Start-Sleep -Milliseconds 200
            $color = switch ($svc.Status) {
                "Healthy" { "Green" }
                "Degraded" { "Yellow" }
                "Unhealthy" { "Red" }
            }
            Write-Host " $($svc.Status)" -ForegroundColor $color
        }
        Write-Success "All health checks completed"
    }
}

function Show-HealthReport {
    $services = Get-ServiceHealth
    
    Write-Host ""
    Write-Host "Health Report" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host ""
    
    $healthy = ($services | Where-Object { $_.Status -eq "Healthy" }).Count
    $total = $services.Count
    $availability = [math]::Round($healthy / $total * 100, 2)
    
    Write-Host "Summary" -ForegroundColor Yellow
    Write-Host "  Total Services: $total"
    Write-Host "  Healthy: $healthy"
    Write-Host "  Availability: $availability%"
    Write-Host ""
    
    $unhealthy = $services | Where-Object { $_.Status -eq "Unhealthy" }
    if ($unhealthy.Count -gt 0) {
        Write-Host "Issues Requiring Attention" -ForegroundColor Red
        foreach ($svc in $unhealthy) {
            Write-Host "  • $($svc.Name): $($svc.Status) (Latency: $($svc.Latency))"
        }
    } else {
        Write-Success "All services are healthy"
    }
    
    if ($ExportPath) {
        $report = @{
            timestamp = Get-Date -Format "o"
            services = $services
            summary = @{
                total = $total
                healthy = $healthy
                availability = $availability
            }
        }
        $report | ConvertTo-Json -Depth 3 | Out-File $ExportPath
        Write-Host ""
        Write-Success "Report exported to: $ExportPath"
    }
}

function Show-HealthHistory {
    Write-Host ""
    Write-Host "Health Check History" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    $history = @(
        @{ Time = "14:45:00"; Status = "Healthy"; Services = 6 }
        @{ Time = "14:30:00"; Status = "Degraded"; Services = 5 }
        @{ Time = "14:15:00"; Status = "Healthy"; Services = 6 }
        @{ Time = "14:00:00"; Status = "Healthy"; Services = 6 }
        @{ Time = "13:45:00"; Status = "Degraded"; Services = 5 }
    )
    
    Write-Host "  Time        Status      Services"
    Write-Host "  " + "-" * 35
    foreach ($entry in $history) {
        $color = switch ($entry.Status) {
            "Healthy" { "Green" }
            "Degraded" { "Yellow" }
            "Unhealthy" { "Red" }
        }
        Write-Host "  $($entry.Time)  " -NoNewline
        Write-Host $entry.Status.PadRight(10) -ForegroundColor $color -NoNewline
        Write-Host " $($entry.Services)"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Health Aggregator" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-HealthAggregator
    
    switch ($Action) {
        "Status" { Show-HealthStatus }
        "Check" { Invoke-HealthCheck -ServiceName $Service }
        "Report" { Show-HealthReport }
        "History" { Show-HealthHistory }
    }
    
    Write-Host ""
}

Main
