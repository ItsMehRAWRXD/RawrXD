#!/usr/bin/env pwsh
# Phase 16 - 24-Hour Monitoring Script
# Runs every 5 minutes to collect metrics

param(
    [string]$LogPath = "d:\rawrxd\monitoring\phase16_24h.jsonl",
    [int]$AlertThresholdP95 = 4000,  # microseconds
    [int]$AlertThresholdP99 = 8000,  # microseconds
    [float]$AlertThresholdAcceptance = 85.0
)

# Ensure monitoring directory exists
$monitorDir = Split-Path $LogPath -Parent
if (!(Test-Path $monitorDir)) {
    New-Item -ItemType Directory -Path $monitorDir -Force | Out-Null
}

# Collect metrics
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# Simulate metric collection (replace with actual telemetry bridge calls)
$metrics = @{
    timestamp = $timestamp
    epoch = $epoch
    window = "24h_monitor"
    
    # Latency metrics (microseconds)
    p50_latency_us = 1579
    p95_latency_us = 2681
    p99_latency_us = 3145
    
    # Quality metrics
    acceptance_rate = 90.5
    cache_hit_rate = 24.4
    
    # System metrics
    memory_kb = 808
    bg_thread_av_count = 3
    
    # Status
    status = "HEALTHY"
    alerts = @()
}

# Check alert thresholds
$alerts = @()

if ($metrics.p95_latency_us -gt $AlertThresholdP95) {
    $alerts += "P95_LATENCY_EXCEEDED: $($metrics.p95_latency_us)us > ${AlertThresholdP95}us"
}

if ($metrics.p99_latency_us -gt $AlertThresholdP99) {
    $alerts += "P99_LATENCY_EXCEEDED: $($metrics.p99_latency_us)us > ${AlertThresholdP99}us"
}

if ($metrics.acceptance_rate -lt $AlertThresholdAcceptance) {
    $alerts += "ACCEPTANCE_RATE_LOW: $($metrics.acceptance_rate)% < ${AlertThresholdAcceptance}%"
}

if ($alerts.Count -gt 0) {
    $metrics.status = "ALERT"
    $metrics.alerts = $alerts
    
    # Write to alert log
    $alertLog = Join-Path $monitorDir "alerts.log"
    foreach ($alert in $alerts) {
        "[$timestamp] ALERT: $alert" | Add-Content $alertLog
    }
}

# Write metrics to JSONL
$jsonLine = $metrics | ConvertTo-Json -Compress
$jsonLine | Add-Content $LogPath

# Output summary
Write-Host "[$timestamp] Status: $($metrics.status) | P95: $($metrics.p95_latency_us)us | Acceptance: $($metrics.acceptance_rate)%"

if ($alerts.Count -gt 0) {
    Write-Host "ALERTS: $($alerts -join '; ')" -ForegroundColor Red
}

# Return status for automation
exit ($alerts.Count -gt 0 ? 1 : 0)
