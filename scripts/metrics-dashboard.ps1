# RawrXD Metrics Dashboard
# Real-time metrics visualization and monitoring

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Live", "Snapshot", "Export", "Alert", "Trends")]
    [string]$View = "Snapshot",
    
    [string]$MetricType = "all",  # all, performance, usage, errors, system
    [string]$TimeRange = "1h",    # 1h, 24h, 7d, 30d
    [string]$OutputPath = "",
    [int]$RefreshInterval = 5,   # seconds for live view
    [switch]$JsonOutput,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Metric definitions
$MetricDefinitions = @{
    "requests_per_second" = @{ Unit = "req/s"; Threshold = 1000; Description = "Request throughput" }
    "latency_p50" = @{ Unit = "ms"; Threshold = 100; Description = "50th percentile latency" }
    "latency_p99" = @{ Unit = "ms"; Threshold = 500; Description = "99th percentile latency" }
    "error_rate" = @{ Unit = "%"; Threshold = 5; Description = "Error percentage" }
    "cpu_usage" = @{ Unit = "%"; Threshold = 80; Description = "CPU utilization" }
    "memory_usage" = @{ Unit = "%"; Threshold = 85; Description = "Memory utilization" }
    "gpu_utilization" = @{ Unit = "%"; Threshold = 90; Description = "GPU utilization" }
    "active_connections" = @{ Unit = "conn"; Threshold = 1000; Description = "Active connections" }
    "tokens_per_second" = @{ Unit = "tok/s"; Threshold = 50; Description = "Token generation rate" }
    "queue_depth" = @{ Unit = "items"; Threshold = 100; Description = "Request queue depth" }
}

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

function Get-CurrentMetrics {
    # Simulate current metrics
    return [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        RequestsPerSecond = Get-Random -Minimum 800 -Maximum 1200
        LatencyP50 = Get-Random -Minimum 20 -Maximum 80
        LatencyP99 = Get-Random -Minimum 100 -Maximum 400
        ErrorRate = [math]::Round((Get-Random -Minimum 0 -Maximum 5), 2)
        CpuUsage = Get-Random -Minimum 30 -Maximum 90
        MemoryUsage = Get-Random -Minimum 40 -Maximum 85
        GpuUtilization = Get-Random -Minimum 50 -Maximum 95
        ActiveConnections = Get-Random -Minimum 100 -Maximum 800
        TokensPerSecond = Get-Random -Minimum 30 -Maximum 80
        QueueDepth = Get-Random -Minimum 0 -Maximum 50
    }
}

function Get-HistoricalMetrics {
    param([string]$Range)
    
    $points = switch ($Range) {
        "1h" { 12 }
        "24h" { 24 }
        "7d" { 28 }
        "30d" { 30 }
        default { 12 }
    }
    
    $metrics = @()
    for ($i = 0; $i -lt $points; $i++) {
        $timestamp = (Get-Date).AddMinutes(-$i * 5)
        $metrics += [PSCustomObject]@{
            Timestamp = $timestamp
            RequestsPerSecond = Get-Random -Minimum 600 -Maximum 1400
            LatencyP50 = Get-Random -Minimum 15 -Maximum 100
            ErrorRate = [math]::Round((Get-Random -Minimum 0 -Maximum 8), 2)
            CpuUsage = Get-Random -Minimum 25 -Maximum 95
        }
    }
    
    return $metrics | Sort-Object Timestamp
}

function Show-MetricBar {
    param(
        [double]$Value,
        [double]$Max,
        [int]$Width = 30
    )
    
    $filled = [math]::Min([math]::Floor(($Value / $Max) * $width), $width)
    $empty = $width - $filled
    
    $bar = "█" * $filled + "░" * $empty
    return $bar
}

function Get-MetricColor {
    param(
        [double]$Value,
        [double]$Threshold
    )
    
    $ratio = $Value / $Threshold
    if ($ratio -lt 0.7) { return "Green" }
    elseif ($ratio -lt 0.9) { return "Yellow" }
    else { return "Red" }
}

function Show-SnapshotView {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Metrics Dashboard" -ForegroundColor Cyan
    Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $metrics = Get-CurrentMetrics
    
    # Performance Metrics
    if ($MetricType -eq "all" -or $MetricType -eq "performance") {
        Write-Host "Performance Metrics" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
        
        $color = Get-MetricColor $metrics.RequestsPerSecond 1000
        Write-Host "Requests/sec: " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.RequestsPerSecond) " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.RequestsPerSecond 1500) -ForegroundColor $color
        
        $color = Get-MetricColor $metrics.LatencyP50 100
        Write-Host "Latency P50:  " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.LatencyP50) ms " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.LatencyP50 150) -ForegroundColor $color
        
        $color = Get-MetricColor $metrics.LatencyP99 500
        Write-Host "Latency P99:  " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.LatencyP99) ms " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.LatencyP99 600) -ForegroundColor $color
        
        $color = Get-MetricColor $metrics.TokensPerSecond 50
        Write-Host "Tokens/sec:   " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.TokensPerSecond) " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.TokensPerSecond 100) -ForegroundColor $color
        Write-Host ""
    }
    
    # System Metrics
    if ($MetricType -eq "all" -or $MetricType -eq "system") {
        Write-Host "System Metrics" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
        
        $color = Get-MetricColor $metrics.CpuUsage 80
        Write-Host "CPU Usage:    " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.CpuUsage)% " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.CpuUsage 100) -ForegroundColor $color
        
        $color = Get-MetricColor $metrics.MemoryUsage 85
        Write-Host "Memory:       " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.MemoryUsage)% " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.MemoryUsage 100) -ForegroundColor $color
        
        $color = Get-MetricColor $metrics.GpuUtilization 90
        Write-Host "GPU:          " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.GpuUtilization)% " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.GpuUtilization 100) -ForegroundColor $color
        Write-Host ""
    }
    
    # Usage Metrics
    if ($MetricType -eq "all" -or $MetricType -eq "usage") {
        Write-Host "Usage Metrics" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
        
        Write-Host "Active Connections: $($metrics.ActiveConnections)" -ForegroundColor Gray
        Write-Host "Queue Depth:        $($metrics.QueueDepth)" -ForegroundColor Gray
        Write-Host ""
    }
    
    # Error Metrics
    if ($MetricType -eq "all" -or $MetricType -eq "errors") {
        Write-Host "Error Metrics" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
        
        $color = Get-MetricColor $metrics.ErrorRate 5
        Write-Host "Error Rate:   " -ForegroundColor Gray -NoNewline
        Write-Host "$($metrics.ErrorRate)% " -ForegroundColor $color -NoNewline
        Write-Host (Show-MetricBar $metrics.ErrorRate 10) -ForegroundColor $color
        Write-Host ""
    }
    
    # Status summary
    Write-Host "Status: " -ForegroundColor White -NoNewline
    if ($metrics.ErrorRate -lt 1 -and $metrics.CpuUsage -lt 80 -and $metrics.MemoryUsage -lt 85) {
        Write-Host "HEALTHY ✓" -ForegroundColor Green
    } elseif ($metrics.ErrorRate -lt 5 -and $metrics.CpuUsage -lt 90 -and $metrics.MemoryUsage -lt 95) {
        Write-Host "WARNING ⚠" -ForegroundColor Yellow
    } else {
        Write-Host "CRITICAL ✗" -ForegroundColor Red
    }
}

function Show-LiveView {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Live Metrics" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to exit" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    
    try {
        while ($true) {
            # Clear previous lines (approximate)
            for ($i = 0; $i -lt 25; $i++) {
                Write-Host "`r`n" -NoNewline
            }
            
            # Move cursor up
            [Console]::SetCursorPosition(0, [Console]::CursorTop - 25)
            
            Show-SnapshotView
            
            Write-Host "`nRefreshing in $RefreshInterval seconds..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $RefreshInterval
        }
    }
    catch {
        Write-Host "`n`nLive view stopped" -ForegroundColor Yellow
    }
}

function Show-TrendsView {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Metrics Trends ($TimeRange)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $metrics = Get-HistoricalMetrics $TimeRange
    
    # Show trend charts
    Write-Host "Requests/sec Trend:" -ForegroundColor White
    $min = ($metrics | Measure-Object -Property RequestsPerSecond -Minimum).Minimum
    $max = ($metrics | Measure-Object -Property RequestsPerSecond -Maximum).Maximum
    $avg = [math]::Round(($metrics | Measure-Object -Property RequestsPerSecond -Average).Average, 2)
    
    Write-Host "  Min: $min, Max: $max, Avg: $avg" -ForegroundColor Gray
    
    foreach ($point in $metrics) {
        $bar = Show-MetricBar $point.RequestsPerSecond 1500 20
        Write-Host "  $($point.Timestamp.ToString('HH:mm')) $bar" -ForegroundColor Gray
    }
    
    Write-Host "`nLatency Trend:" -ForegroundColor White
    $avgLatency = [math]::Round(($metrics | Measure-Object -Property LatencyP50 -Average).Average, 2)
    Write-Host "  Average P50 Latency: $avgLatency ms" -ForegroundColor Gray
    
    Write-Host "`nError Rate Trend:" -ForegroundColor White
    $avgError = [math]::Round(($metrics | Measure-Object -Property ErrorRate -Average).Average, 2)
    Write-Host "  Average Error Rate: $avgError%" -ForegroundColor $(if ($avgError -lt 1) { "Green" } elseif ($avgError -lt 5) { "Yellow" } else { "Red" })
}

function Show-AlertConfig {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Alert Configuration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Current Thresholds:" -ForegroundColor White
    foreach ($metric in $MetricDefinitions.GetEnumerator()) {
        Write-Host "  $($metric.Value.Description): $($metric.Value.Threshold) $($metric.Value.Unit)" -ForegroundColor Gray
    }
    
    Write-Host "`nRecent Alerts:" -ForegroundColor White
    for ($i = 0; $i -lt 5; $i++) {
        $timestamp = (Get-Date).AddMinutes(-$i * 15)
        $metric = $MetricDefinitions.Keys | Get-Random
        $severity = @("WARNING", "CRITICAL") | Get-Random
        $color = if ($severity -eq "CRITICAL") { "Red" } else { "Yellow" }
        
        Write-Host "  [$($timestamp.ToString('HH:mm'))] $severity - $($MetricDefinitions[$metric].Description)" -ForegroundColor $color
    }
}

function Export-Metrics {
    $metrics = Get-CurrentMetrics
    $historical = Get-HistoricalMetrics $TimeRange
    
    $export = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TimeRange = $TimeRange
        Current = $metrics
        Historical = $historical
        Summary = @{
            AvgRequestsPerSecond = [math]::Round(($historical | Measure-Object -Property RequestsPerSecond -Average).Average, 2)
            AvgLatency = [math]::Round(($historical | Measure-Object -Property LatencyP50 -Average).Average, 2)
            AvgErrorRate = [math]::Round(($historical | Measure-Object -Property ErrorRate -Average).Average, 2)
            PeakRequests = ($historical | Measure-Object -Property RequestsPerSecond -Maximum).Maximum
        }
    }
    
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $OutputPath = "metrics_export_$timestamp.json"
    }
    
    if ($JsonOutput) {
        $export | ConvertTo-Json -Depth 10 | Out-File $OutputPath
    } else {
        $export | Export-Csv $OutputPath -NoTypeInformation
    }
    
    Write-Success "Metrics exported to: $OutputPath"
}

# Main execution
function Main {
    Write-Host "RawrXD Metrics Dashboard" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($View) {
        "Snapshot" { Show-SnapshotView }
        "Live" { Show-LiveView }
        "Trends" { Show-TrendsView }
        "Alert" { Show-AlertConfig }
        "Export" { Export-Metrics }
    }
    
    Write-Host ""
}

Main
