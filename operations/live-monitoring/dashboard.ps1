# dashboard.ps1
# Phase K Batch 1/5: Live Operations Dashboard

param(
    [string]$Endpoint = "http://localhost:8080",
    [int]$RefreshInterval = 5
)

$ErrorActionPreference = "Continue"

function Clear-Screen {
    Clear-Host
}

function Write-DashboardHeader {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RAWRXD SOVEREIGN - LIVE OPERATIONS DASHBOARD          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-SystemStatus {
    try {
        $health = Invoke-RestMethod -Uri "$Endpoint/api/v1/health" -TimeoutSec 2 -ErrorAction Stop
        return $health
    }
    catch {
        return @{ status = "unavailable"; components = @{} }
    }
}

function Get-PerformanceMetrics {
    try {
        $metrics = Invoke-RestMethod -Uri "$Endpoint/api/v1/metrics" -TimeoutSec 2 -ErrorAction Stop
        return $metrics
    }
    catch {
        return @{ tps = 0; latency_avg_ms = 0; latency_p95_ms = 0; active_requests = 0 }
    }
}

function Get-SystemResources {
    try {
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem
        $memoryUsed = (($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100
        $disk = Get-PSDrive -Name C
        
        return @{
            cpu = [math]::Round($cpu, 1)
            memory = [math]::Round($memoryUsed, 1)
            diskFree = [math]::Round($disk.Free / 1GB, 2)
        }
    }
    catch {
        return @{ cpu = 0; memory = 0; diskFree = 0 }
    }
}

function Show-StatusPanel($Status) {
    Write-Host "┌─ SYSTEM STATUS ─────────────────────────────────────────────────┐" -ForegroundColor Gray
    
    $statusColor = if ($Status.status -eq "healthy") { "Green" } elseif ($Status.status -eq "degraded") { "Yellow" } else { "Red" }
    Write-Host "│ Overall Status: " -NoNewline -ForegroundColor Gray
    Write-Host "$($Status.status.ToUpper())" -ForegroundColor $statusColor
    
    if ($Status.components) {
        foreach ($component in $Status.components.GetEnumerator()) {
            $compColor = if ($component.Value -eq "healthy") { "Green" } else { "Red" }
            Write-Host "│   $($component.Key): " -NoNewline -ForegroundColor Gray
            Write-Host "$($component.Value)" -ForegroundColor $compColor
        }
    }
    
    Write-Host "└─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-PerformancePanel($Metrics) {
    Write-Host "┌─ PERFORMANCE METRICS ───────────────────────────────────────────┐" -ForegroundColor Gray
    
    $tpsColor = if ($Metrics.tps -ge 40) { "Green" } elseif ($Metrics.tps -ge 30) { "Yellow" } else { "Red" }
    Write-Host "│ TPS: " -NoNewline -ForegroundColor Gray
    Write-Host "$([math]::Round($Metrics.tps, 1))" -NoNewline -ForegroundColor $tpsColor
    Write-Host " req/s" -ForegroundColor Gray
    
    $latColor = if ($Metrics.latency_p95_ms -le 100) { "Green" } elseif ($Metrics.latency_p95_ms -le 200) { "Yellow" } else { "Red" }
    Write-Host "│ Latency P95: " -NoNewline -ForegroundColor Gray
    Write-Host "$([math]::Round($Metrics.latency_p95_ms, 1))" -NoNewline -ForegroundColor $latColor
    Write-Host " ms" -ForegroundColor Gray
    
    Write-Host "│ Latency Avg: " -NoNewline -ForegroundColor Gray
    Write-Host "$([math]::Round($Metrics.latency_avg_ms, 1))" -NoNewline -ForegroundColor White
    Write-Host " ms" -ForegroundColor Gray
    
    Write-Host "│ Active Requests: " -NoNewline -ForegroundColor Gray
    Write-Host "$($Metrics.active_requests)" -ForegroundColor White
    
    Write-Host "└─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-ResourcesPanel($Resources) {
    Write-Host "┌─ SYSTEM RESOURCES ──────────────────────────────────────────────┐" -ForegroundColor Gray
    
    $cpuColor = if ($Resources.cpu -lt 70) { "Green" } elseif ($Resources.cpu -lt 85) { "Yellow" } else { "Red" }
    Write-Host "│ CPU Usage: " -NoNewline -ForegroundColor Gray
    Write-Host "$($Resources.cpu)%" -NoNewline -ForegroundColor $cpuColor
    Write-Host " " -NoNewline
    Show-ProgressBar -Value $Resources.cpu -Max 100 -Width 30
    
    $memColor = if ($Resources.memory -lt 80) { "Green" } elseif ($Resources.memory -lt 90) { "Yellow" } else { "Red" }
    Write-Host "│ Memory: " -NoNewline -ForegroundColor Gray
    Write-Host "$($Resources.memory)%" -NoNewline -ForegroundColor $memColor
    Write-Host " " -NoNewline
    Show-ProgressBar -Value $Resources.memory -Max 100 -Width 30
    
    $diskColor = if ($Resources.diskFree -gt 20) { "Green" } elseif ($Resources.diskFree -gt 10) { "Yellow" } else { "Red" }
    Write-Host "│ Disk Free: " -NoNewline -ForegroundColor Gray
    Write-Host "$($Resources.diskFree) GB" -ForegroundColor $diskColor
    
    Write-Host "└─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-ProgressBar($Value, $Max, $Width) {
    $filled = [math]::Round(($Value / $Max) * $Width)
    $empty = $Width - $filled
    
    $bar = "█" * $filled + "░" * $empty
    Write-Host "[$bar]" -ForegroundColor Gray
}

function Show-AlertsPanel {
    Write-Host "┌─ ACTIVE ALERTS ─────────────────────────────────────────────────┐" -ForegroundColor Gray
    
    $alertsFile = "${env:ProgramData}\RawrXD\logs\alerts.log"
    if (Test-Path $alertsFile) {
        $recentAlerts = Get-Content $alertsFile -Tail 5 | Select-String "CRITICAL|WARNING"
        if ($recentAlerts) {
            foreach ($alert in $recentAlerts) {
                if ($alert -match "CRITICAL") {
                    Write-Host "│ ⚠️  $alert" -ForegroundColor Red
                } else {
                    Write-Host "│ ⚡ $alert" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "│ ✅ No active alerts" -ForegroundColor Green
        }
    } else {
        Write-Host "│ ℹ️  Alert log not found" -ForegroundColor Gray
    }
    
    Write-Host "└─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-Footer {
    Write-Host "Press Ctrl+C to exit | Refresh: ${RefreshInterval}s | Endpoint: $Endpoint" -ForegroundColor DarkGray
}

# Main loop
while ($true) {
    Clear-Screen
    Write-DashboardHeader
    
    $status = Get-SystemStatus
    $metrics = Get-PerformanceMetrics
    $resources = Get-SystemResources
    
    Show-StatusPanel -Status $status
    Show-PerformancePanel -Metrics $metrics
    Show-ResourcesPanel -Resources $resources
    Show-AlertsPanel
    Show-Footer
    
    Start-Sleep -Seconds $RefreshInterval
}
