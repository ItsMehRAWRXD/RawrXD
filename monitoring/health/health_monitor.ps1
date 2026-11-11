#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Health Monitoring & Alerting
# Phase G.1 Batch 2/5: Health Dashboard & Threshold Alerts
#==============================================================================
# Monitors sovereign health with threshold-based alerting
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\telemetry\telemetry_data",

    [Parameter()]
    [string]$ConfigPath = ".\health_config.json",

    [Parameter()]
    [string]$OutputPath = ".\health_status",

    [Parameter()]
    [switch]$EnableWebhooks,

    [Parameter()]
    [string]$WebhookUrl = "",

    [Parameter()]
    [switch]$RunContinuous
)

#==============================================================================
# Health Configuration
#==============================================================================

$script:HealthConfig = @{
    Version = "1.0.0"
    CheckIntervalSeconds = 10
    
    Thresholds = @{
        TPS = @{ Warning = 35; Critical = 25; Unit = "tokens/sec" }
        TTFT = @{ Warning = 30; Critical = 50; Unit = "ms" }
        Latency = @{ Warning = 50; Critical = 100; Unit = "ms" }
        Memory = @{ Warning = 6144; Critical = 8192; Unit = "MB" }
        GPU = @{ Warning = 85; Critical = 95; Unit = "percent" }
        SIS = @{ Warning = 85; Critical = 75; Unit = "score" }
    }
    
    AlertCooldownMinutes = 5
    
    Webhooks = @{
        Enabled = $false
        Url = ""
        Headers = @{ "Content-Type" = "application/json" }
        TimeoutSeconds = 30
    }
}

#==============================================================================
# Health Monitor Classes
#==============================================================================

class HealthMonitor {
    [string]$TelemetryPath
    [string]$ConfigPath
    [string]$OutputPath
    [hashtable]$Config
    [hashtable]$CurrentHealth
    [hashtable]$LastAlertTime
    [System.Collections.ArrayList]$AlertHistory
    [bool]$IsRunning

    HealthMonitor([string]$telemetry, [string]$config, [string]$output) {
        $this.TelemetryPath = $telemetry
        $this.ConfigPath = $config
        $this.OutputPath = $output
        $this.CurrentHealth = @{}
        $this.LastAlertTime = @{}
        $this.AlertHistory = @()
        $this.IsRunning = $false
    }

    [void] Initialize() {
        Write-Host "`n=== Initializing Health Monitor ===" -ForegroundColor Cyan
        
        New-Item -ItemType Directory -Force -Path $this.OutputPath | Out-Null
        
        # Load or create config
        if (Test-Path $this.ConfigPath) {
            $this.Config = Get-Content $this.ConfigPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Config loaded from: $($this.ConfigPath)" -ForegroundColor Green
        }
        else {
            $this.Config = $script:HealthConfig
            $this.Config | ConvertTo-Json -Depth 10 | Out-File $this.ConfigPath
            Write-Host "✓ Default config created: $($this.ConfigPath)" -ForegroundColor Green
        }
        
        Write-Host "Check Interval: $($this.Config.CheckIntervalSeconds)s" -ForegroundColor White
        Write-Host "Alert Cooldown: $($this.Config.AlertCooldownMinutes) minutes" -ForegroundColor White
    }

    [hashtable] LoadLatestTelemetry() {
        $latestFile = Get-ChildItem -Path $this.TelemetryPath -Filter "telemetry_*.jsonl" | 
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        
        if (-not $latestFile) {
            return @{}
        }
        
        # Read last line (most recent)
        $lines = Get-Content $latestFile.FullName -Tail 1
        if ($lines) {
            return ($lines | ConvertFrom-Json -AsHashtable)
        }
        
        return @{}
    }

    [hashtable] CalculateHealth([hashtable]$telemetry) {
        $health = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Overall = "HEALTHY"
            Metrics = @{}
            Alerts = @()
        }
        
        if (-not $telemetry.Collection) {
            $health.Overall = "UNKNOWN"
            return $health
        }
        
        $metrics = $telemetry.Collection
        
        # Check TPS
        if ($metrics.TPS) {
            $tpsStatus = $this.CheckThreshold("TPS", $metrics.TPS)
            $health.Metrics.TPS = @{ Value = $metrics.TPS; Status = $tpsStatus.Status }
            if ($tpsStatus.Alert) { $health.Alerts += $tpsStatus.Alert }
        }
        
        # Check TTFT
        if ($metrics.TTFT_ms) {
            $ttftStatus = $this.CheckThreshold("TTFT", $metrics.TTFT_ms)
            $health.Metrics.TTFT = @{ Value = $metrics.TTFT_ms; Status = $ttftStatus.Status }
            if ($ttftStatus.Alert) { $health.Alerts += $ttftStatus.Alert }
        }
        
        # Check Latency
        if ($metrics.Latency_ms) {
            $latStatus = $this.CheckThreshold("Latency", $metrics.Latency_ms)
            $health.Metrics.Latency = @{ Value = $metrics.Latency_ms; Status = $latStatus.Status }
            if ($latStatus.Alert) { $health.Alerts += $latStatus.Alert }
        }
        
        # Check Memory
        if ($metrics.MemoryUsage_MB) {
            $memStatus = $this.CheckThreshold("Memory", $metrics.MemoryUsage_MB)
            $health.Metrics.Memory = @{ Value = $metrics.MemoryUsage_MB; Status = $memStatus.Status }
            if ($memStatus.Alert) { $health.Alerts += $memStatus.Alert }
        }
        
        # Check GPU
        if ($metrics.GPUUtilization_Percent) {
            $gpuStatus = $this.CheckThreshold("GPU", $metrics.GPUUtilization_Percent)
            $health.Metrics.GPU = @{ Value = $metrics.GPUUtilization_Percent; Status = $gpuStatus.Status }
            if ($gpuStatus.Alert) { $health.Alerts += $gpuStatus.Alert }
        }
        
        # Determine overall health
        $criticalCount = ($health.Metrics.Values | Where-Object { $_.Status -eq "CRITICAL" }).Count
        $warningCount = ($health.Metrics.Values | Where-Object { $_.Status -eq "WARNING" }).Count
        
        if ($criticalCount -gt 0) { $health.Overall = "CRITICAL" }
        elseif ($warningCount -gt 0) { $health.Overall = "WARNING" }
        else { $health.Overall = "HEALTHY" }
        
        return $health
    }

    [hashtable] CheckThreshold([string]$metric, [double]$value) {
        $threshold = $this.Config.Thresholds[$metric]
        $result = @{ Status = "HEALTHY"; Alert = $null }
        
        if (-not $threshold) { return $result }
        
        # For metrics where lower is better (TTFT, Latency, Memory)
        $lowerIsBetter = @("TTFT", "Latency", "Memory")
        
        if ($metric -in $lowerIsBetter) {
            if ($value -gt $threshold.Critical) {
                $result.Status = "CRITICAL"
                $result.Alert = $this.CreateAlert($metric, $value, "CRITICAL", $threshold)
            }
            elseif ($value -gt $threshold.Warning) {
                $result.Status = "WARNING"
                $result.Alert = $this.CreateAlert($metric, $value, "WARNING", $threshold)
            }
        }
        else {
            # For metrics where higher is better (TPS)
            if ($value -lt $threshold.Critical) {
                $result.Status = "CRITICAL"
                $result.Alert = $this.CreateAlert($metric, $value, "CRITICAL", $threshold)
            }
            elseif ($value -lt $threshold.Warning) {
                $result.Status = "WARNING"
                $result.Alert = $this.CreateAlert($metric, $value, "WARNING", $threshold)
            }
        }
        
        return $result
    }

    [hashtable] CreateAlert([string]$metric, [double]$value, [string]$severity, [hashtable]$threshold) {
        $alertKey = "$metric-$severity"
        $now = Get-Date
        
        # Check cooldown
        if ($this.LastAlertTime.ContainsKey($alertKey)) {
            $lastAlert = $this.LastAlertTime[$alertKey]
            $cooldown = [TimeSpan]::FromMinutes($this.Config.AlertCooldownMinutes)
            if (($now - $lastAlert) -lt $cooldown) {
                return $null  # Still in cooldown
            }
        }
        
        $alert = @{
            Timestamp = $now.ToString("yyyy-MM-ddTHH:mm:ssZ")
            Metric = $metric
            Value = $value
            Severity = $severity
            Threshold = $threshold
            Message = "$severity`: $metric is $value (threshold: $($threshold.Warning)-$($threshold.Critical))"
        }
        
        $this.LastAlertTime[$alertKey] = $now
        $this.AlertHistory.Add($alert)
        
        return $alert
    }

    [void] SendWebhook([hashtable]$health) {
        if (-not $this.Config.Webhooks.Enabled -or $health.Alerts.Count -eq 0) { return }
        
        $payload = @{
            text = "RawrXD Health Alert"
            health = $health.Overall
            alerts = $health.Alerts
            timestamp = $health.Timestamp
        } | ConvertTo-Json -Depth 5
        
        try {
            $response = Invoke-RestMethod -Uri $this.Config.Webhooks.Url -Method Post `
                -Body $payload -Headers $this.Config.Webhooks.Headers `
                -TimeoutSec $this.Config.Webhooks.TimeoutSeconds
            Write-Verbose "Webhook sent successfully"
        }
        catch {
            Write-Warning "Failed to send webhook: $_"
        }
    }

    [void] OutputHealth([hashtable]$health) {
        # Save to file
        $healthFile = Join-Path $this.OutputPath "health_status.json"
        $health | ConvertTo-Json -Depth 10 | Out-File $healthFile
        
        # Console output
        $color = switch ($health.Overall) {
            "HEALTHY" { "Green" }
            "WARNING" { "Yellow" }
            "CRITICAL" { "Red" }
            default { "Gray" }
        }
        
        $time = [DateTime]::Parse($health.Timestamp).ToString("HH:mm:ss")
        Write-Host "[$time] Health: " -NoNewline -ForegroundColor Gray
        Write-Host $health.Overall -ForegroundColor $color -NoNewline
        
        if ($health.Alerts.Count -gt 0) {
            Write-Host " | Alerts: $($health.Alerts.Count)" -ForegroundColor Red
            foreach ($alert in $health.Alerts) {
                Write-Host "  ⚠ $($alert.Message)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host " | All metrics nominal" -ForegroundColor Green
        }
    }

    [void] RunMonitoring() {
        Write-Host "`n=== Starting Health Monitoring ===" -ForegroundColor Cyan
        Write-Host "Press Ctrl+C to stop...`n" -ForegroundColor Gray
        
        $this.IsRunning = $true
        
        while ($this.IsRunning) {
            $telemetry = $this.LoadLatestTelemetry()
            $health = $this.CalculateHealth($telemetry)
            $this.CurrentHealth = $health
            
            $this.OutputHealth($health)
            $this.SendWebhook($health)
            
            Start-Sleep -Seconds $this.Config.CheckIntervalSeconds
        }
    }

    [void] GenerateDashboard() {
        Write-Host "`n=== Generating Health Dashboard ===" -ForegroundColor Cyan
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Sovereign Health Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; }
        .status-card { background: white; padding: 30px; border-radius: 10px; margin: 20px 0; }
        .healthy { border-left: 5px solid #4caf50; }
        .warning { border-left: 5px solid #ff9800; }
        .critical { border-left: 5px solid #f44336; }
        .metric { display: inline-block; margin: 10px 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .metric-value { font-size: 24px; font-weight: bold; }
        .metric-label { font-size: 12px; color: #666; }
        h1 { color: #333; }
        .timestamp { color: #888; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ RawrXD Sovereign Health Dashboard</h1>
        <div class="timestamp">Last Updated: $($this.CurrentHealth.Timestamp)</div>
        
        <div class="status-card $($this.CurrentHealth.Overall.ToLower())">
            <h2>Overall Status: $($this.CurrentHealth.Overall)</h2>
            <div class="metrics">
"@

        foreach ($metric in $this.CurrentHealth.Metrics.Keys) {
            $m = $this.CurrentHealth.Metrics[$metric]
            $html += @"
                <div class="metric">
                    <div class="metric-value">$($m.Value)</div>
                    <div class="metric-label">$metric ($($m.Status))</div>
                </div>
"@
        }

        $html += @"
            </div>
        </div>
        
        <div class="status-card">
            <h2>Recent Alerts</h2>
"@

        if ($this.AlertHistory.Count -eq 0) {
            $html += "<p>No alerts in history</p>"
        }
        else {
            $html += "<ul>"
            foreach ($alert in ($this.AlertHistory | Select-Object -Last 10)) {
                $html += "<li>[$($alert.Timestamp)] $($alert.Severity): $($alert.Message)</li>"
            }
            $html += "</ul>"
        }

        $html += @"
        </div>
    </div>
</body>
</html>
"@

        $dashboardPath = Join-Path $this.OutputPath "dashboard.html"
        $html | Out-File $dashboardPath
        Write-Host "✓ Dashboard saved: $dashboardPath" -ForegroundColor Green
    }

    [void] Stop() {
        $this.IsRunning = $false
        $this.GenerateDashboard()
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Health Monitoring & Alerting                    ║
║           Phase G.1 Batch 2/5: Health Dashboard & Threshold Alerts             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$monitor = [HealthMonitor]::new($TelemetryPath, $ConfigPath, $OutputPath)
$monitor.Initialize()

if ($EnableWebhooks -and $WebhookUrl) {
    $monitor.Config.Webhooks.Enabled = $true
    $monitor.Config.Webhooks.Url = $WebhookUrl
}

if ($RunContinuous) {
    # Handle Ctrl+C
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        $monitor.Stop()
    }
    
    try {
        $monitor.RunMonitoring()
    }
    finally {
        $monitor.GenerateDashboard()
    }
}
else {
    # Single check
    $telemetry = $monitor.LoadLatestTelemetry()
    $health = $monitor.CalculateHealth($telemetry)
    $monitor.OutputHealth($health)
    $monitor.GenerateDashboard()
}
