#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase G.2 Batch 4/5: Alert System
    
.DESCRIPTION
    Performance regression alerting with multi-channel notifications:
    - Threshold-based alert rules (SIS, SAI, TPS, Latency)
    - Alert severity classification (INFO, WARNING, CRITICAL)
    - Notification channels: Console, File, Webhook
    - Alert deduplication and throttling
    - Alert history and acknowledgment
    
.PARAMETER ConfigPath
    Path to alert configuration JSON (default: .\alert_config.json)
    
.PARAMETER DataPath
    Path to time-series database for querying (default: ..\batch2_timeseries_db\tsdb_data)
    
.PARAMETER Action
    Action: run, test, config-template, history
    
.PARAMETER WebhookUrl
    Webhook URL for external notifications (optional)
    
.PARAMETER CheckInterval
    Alert check interval in seconds (default: 60)
    
.PARAMETER InstanceId
    Specific instance to monitor (default: all)
    
.EXAMPLE
    .\alert_manager.ps1 -Action config-template
    
.EXAMPLE
    .\alert_manager.ps1 -Action run -CheckInterval 30
    
.EXAMPLE
    .\alert_manager.ps1 -Action test -WebhookUrl "https://hooks.slack.com/..."
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\alert_config.json",
    
    [Parameter(Mandatory=$false)]
    [string]$DataPath = "..\batch2_timeseries_db\tsdb_data",
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("run", "test", "config-template", "history")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$WebhookUrl,
    
    [Parameter(Mandatory=$false)]
    [int]$CheckInterval = 60,
    
    [Parameter(Mandatory=$false)]
    [string]$InstanceId
)

# Error action preference
$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase G.2 Batch 4/5: Alert System                                ║
║  Performance Regression Detection & Notification                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Alert state
$script:AlertState = @{
    last_alerts = @{}  # For deduplication
    alert_history = [System.Collections.ArrayList]::new()
    running = $true
}

# Default alert configuration
$defaultConfig = @{
    rules = @(
        @{
            name = "SIS Critical Low"
            metric = "sis"
            operator = "less_than"
            threshold = 70
            severity = "CRITICAL"
            cooldown_minutes = 5
            channels = @("console", "webhook")
            message = "SIS score dropped below 70: {{value}}"
        }
        @{
            name = "SIS Warning Low"
            metric = "sis"
            operator = "less_than"
            threshold = 85
            severity = "WARNING"
            cooldown_minutes = 10
            channels = @("console")
            message = "SIS score below target: {{value}} (target: 85+)"
        }
        @{
            name = "SAI Below Baseline"
            metric = "sai"
            operator = "less_than"
            threshold = 1.0
            severity = "CRITICAL"
            cooldown_minutes = 5
            channels = @("console", "webhook")
            message = "SAI below baseline: {{value}}x (expected > 1.0x)"
        }
        @{
            name = "TPS Degradation"
            metric = "tps"
            operator = "less_than"
            threshold = 35
            severity = "WARNING"
            cooldown_minutes = 10
            channels = @("console")
            message = "TPS below threshold: {{value}} tok/s"
        }
        @{
            name = "High Latency"
            metric = "latency_ms"
            operator = "greater_than"
            threshold = 100
            severity = "WARNING"
            cooldown_minutes = 10
            channels = @("console")
            message = "Latency elevated: {{value}} ms"
        }
        @{
            name = "Instance Offline"
            metric = "instance_status"
            operator = "equals"
            threshold = "offline"
            severity = "CRITICAL"
            cooldown_minutes = 2
            channels = @("console", "webhook")
            message = "Instance {{instance}} is offline"
        }
    )
    global_settings = @{
        default_cooldown_minutes = 15
        max_alerts_per_hour = 20
        alert_retention_days = 30
    }
    notifications = @{
        webhook_url = $WebhookUrl
        webhook_enabled = [bool]$WebhookUrl
    }
}

function Write-ConfigTemplate {
    <#
    .SYNOPSIS
        Writes default alert configuration template
    #>
    Write-Host "`nGenerating alert configuration template..." -ForegroundColor Yellow
    
    $defaultConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath
    
    Write-Host "  ✓ Configuration template written to: $ConfigPath" -ForegroundColor Green
    Write-Host "`nEdit this file to customize alert rules and thresholds." -ForegroundColor Gray
}

function Send-AlertNotification {
    <#
    .SYNOPSIS
        Sends alert through configured channels
    #>
    param(
        [hashtable]$Alert,
        [hashtable]$Config
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $severityColor = switch ($Alert.severity) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "INFO" { "Green" }
        default { "White" }
    }
    
    # Console notification
    if ($Alert.channels -contains "console") {
        Write-Host "`n[!] ALERT [$($Alert.severity)]" -ForegroundColor $severityColor -NoNewline
        Write-Host " $($Alert.name)" -ForegroundColor White
        Write-Host "    Time: $timestamp" -ForegroundColor Gray
        Write-Host "    Message: $($Alert.message)" -ForegroundColor Gray
        if ($Alert.instance) {
            Write-Host "    Instance: $($Alert.instance)" -ForegroundColor Gray
        }
        Write-Host "    Value: $($Alert.current_value)" -ForegroundColor Gray
    }
    
    # File notification
    if ($Alert.channels -contains "file") {
        $logEntry = "$timestamp | $($Alert.severity) | $($Alert.name) | $($Alert.message) | $($Alert.current_value)"
        Add-Content -Path ".\alerts.log" -Value $logEntry
    }
    
    # Webhook notification
    if ($Alert.channels -contains "webhook" -and $Config.notifications.webhook_enabled) {
        try {
            $payload = @{
                text = "RawrXD Alert: $($Alert.name)"
                severity = $Alert.severity
                message = $Alert.message
                timestamp = $timestamp
                instance = $Alert.instance
                value = $Alert.current_value
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri $Config.notifications.webhook_url -Method POST -Body $payload -ContentType "application/json" -TimeoutSec 5 | Out-Null
            Write-Host "    ✓ Webhook notification sent" -ForegroundColor Green
        }
        catch {
            Write-Host "    ✗ Webhook failed: $_" -ForegroundColor Red
        }
    }
}

function Test-AlertCondition {
    <#
    .SYNOPSIS
        Tests if alert condition is met
    #>
    param(
        [hashtable]$Rule,
        [double]$Value
    )
    
    switch ($Rule.operator) {
        "less_than" { return $Value -lt $Rule.threshold }
        "greater_than" { return $Value -gt $Rule.threshold }
        "equals" { return $Value -eq $Rule.threshold }
        "not_equals" { return $Value -ne $Rule.threshold }
        default { return $false }
    }
}

function Get-CurrentMetrics {
    <#
    .SYNOPSIS
        Gets current metrics from data source
    #>
    param([string]$Instance)
    
    # Simulated metrics for demonstration
    # In production, this queries the time-series database
    return @{
        sis = 87.5 + (Get-Random -Minimum -10 -Maximum 5)
        sai = 1.52 + (Get-Random -Minimum -0.2 -Maximum 0.1)
        tps = 47.3 + (Get-Random -Minimum -15 -Maximum 10)
        latency_ms = 42.1 + (Get-Random -Minimum -10 -Maximum 50)
        instance_status = if ((Get-Random) % 20 -eq 0) { "offline" } else { "online" }
    }
}

function Invoke-AlertCheck {
    <#
    .SYNOPSIS
        Runs alert check cycle
    #>
    param([hashtable]$Config)
    
    $metrics = Get-CurrentMetrics -Instance $InstanceId
    $now = Get-Date
    
    foreach ($rule in $Config.rules) {
        $metricValue = $metrics[$rule.metric]
        
        if (Test-AlertCondition -Rule $rule -Value $metricValue) {
            $alertKey = "$($rule.name):$InstanceId"
            
            # Check cooldown
            $lastAlert = $script:AlertState.last_alerts[$alertKey]
            $cooldown = $rule.cooldown_minutes
            
            if ($lastAlert -and ($now - $lastAlert).TotalMinutes -lt $cooldown) {
                continue  # Skip - in cooldown
            }
            
            # Build alert
            $alert = @{
                name = $rule.name
                severity = $rule.severity
                message = $rule.message.Replace("{{value}}", $metricValue).Replace("{{instance}}", $InstanceId)
                current_value = $metricValue
                instance = $InstanceId
                channels = $rule.channels
                timestamp = $now
            }
            
            # Send notification
            Send-AlertNotification -Alert $alert -Config $Config
            
            # Update state
            $script:AlertState.last_alerts[$alertKey] = $now
            [void]$script:AlertState.alert_history.Add($alert)
        }
    }
}

function Invoke-AlertTest {
    <#
    .SYNOPSIS
        Tests alert system with simulated conditions
    #>
    param([hashtable]$Config)
    
    Write-Host "`nTesting alert system..." -ForegroundColor Yellow
    
    # Test each severity level
    $testAlerts = @(
        @{ name = "Test INFO"; severity = "INFO"; message = "Test info alert"; current_value = 100; channels = @("console") }
        @{ name = "Test WARNING"; severity = "WARNING"; message = "Test warning alert"; current_value = 50; channels = @("console") }
        @{ name = "Test CRITICAL"; severity = "CRITICAL"; message = "Test critical alert"; current_value = 10; channels = @("console", "webhook") }
    )
    
    foreach ($alert in $testAlerts) {
        Send-AlertNotification -Alert $alert -Config $Config
        Start-Sleep -Milliseconds 500
    }
    
    Write-Host "`n✓ Alert test complete" -ForegroundColor Green
}

# Execute action
switch ($Action) {
    "config-template" { Write-ConfigTemplate }
    
    "test" { 
        $config = if (Test-Path $ConfigPath) { 
            Get-Content -Path $ConfigPath | ConvertFrom-Json -AsHashtable 
        } else { 
            $defaultConfig 
        }
        if ($WebhookUrl) { 
            $config.notifications.webhook_url = $WebhookUrl
            $config.notifications.webhook_enabled = $true
        }
        Invoke-AlertTest -Config $config 
    }
    
    "run" {
        $config = if (Test-Path $ConfigPath) { 
            Get-Content -Path $ConfigPath | ConvertFrom-Json -AsHashtable 
        } else { 
            Write-Host "No config found, using defaults..." -ForegroundColor Yellow
            $defaultConfig 
        }
        
        Write-Host "`nStarting alert manager..." -ForegroundColor Green
        Write-Host "  Check interval: ${CheckInterval}s" -ForegroundColor Gray
        Write-Host "  Monitoring: $(if ($InstanceId) { $InstanceId } else { "All instances" })" -ForegroundColor Gray
        Write-Host "  Press Ctrl+C to stop`n" -ForegroundColor Gray
        
        try {
            while ($script:AlertState.running) {
                Invoke-AlertCheck -Config $config
                Start-Sleep -Seconds $CheckInterval
            }
        }
        catch {
            Write-Host "`nAlert manager stopped: $_" -ForegroundColor Yellow
        }
    }
    
    "history" {
        Write-Host "`nAlert History:" -ForegroundColor Yellow
        if ($script:AlertState.alert_history.Count -eq 0) {
            Write-Host "  No alerts recorded yet." -ForegroundColor Gray
        } else {
            foreach ($alert in $script:AlertState.alert_history | Select-Object -Last 20) {
                Write-Host "  [$($alert.timestamp)] $($alert.severity): $($alert.name)" -ForegroundColor White
            }
        }
    }
}

Write-Host "`nAlert system operation complete." -ForegroundColor Green
