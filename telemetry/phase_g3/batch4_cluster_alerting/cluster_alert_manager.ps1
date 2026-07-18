#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase G.3 Batch 4/5: Cluster-Wide Alerting
    
.DESCRIPTION
    Multi-node performance regression detection with cluster-aware routing:
    - Cross-node anomaly detection
    - Cascade failure prediction
    - Alert routing by instance/region
    - Maintenance window coordination
    - Cluster health scoring
    
.PARAMETER AggregatorPath
    Path to aggregated metrics (default: ..\batch2_metrics_aggregator\aggregated_metrics)
    
.PARAMETER ConfigPath
    Path to alert configuration (default: .\cluster_alert_config.json)
    
.PARAMETER CheckInterval
    Alert check interval in seconds (default: 60)
    
.PARAMETER WebhookUrl
    Webhook URL for notifications
    
.PARAMETER EnableCascadeDetection
    Enable cascade failure prediction
    
.EXAMPLE
    .\cluster_alert_manager.ps1
    
.EXAMPLE
    .\cluster_alert_manager.ps1 -EnableCascadeDetection -CheckInterval 30
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$AggregatorPath = "..\batch2_metrics_aggregator\aggregated_metrics",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\cluster_alert_config.json",
    
    [Parameter(Mandatory=$false)]
    [int]$CheckInterval = 60,
    
    [Parameter(Mandatory=$false)]
    [string]$WebhookUrl,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableCascadeDetection
)

# Error action preference
$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase G.3 Batch 4/5: Cluster-Wide Alerting                       ║
║  Multi-Node Anomaly Detection & Cascade Failure Prediction        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Alert state
$script:AlertState = @{
    last_alerts = @{}
    alert_history = [System.Collections.ArrayList]::new()
    running = $true
    cascade_detected = $false
}

# Default cluster alert configuration
$defaultConfig = @{
    cluster_rules = @(
        @{
            name = "Cluster TPS Critical Drop"
            metric = "cluster_tps"
            operator = "less_than"
            threshold = 100
            severity = "CRITICAL"
            cooldown_minutes = 5
            channels = @("console", "webhook")
            message = "Cluster TPS dropped to {{value}} (threshold: {{threshold}})"
        }
        @{
            name = "Node Response Rate Low"
            metric = "response_rate"
            operator = "less_than"
            threshold = 80
            severity = "WARNING"
            cooldown_minutes = 10
            channels = @("console")
            message = "Only {{value}}% of nodes responding"
        }
        @{
            name = "High TPS Variance"
            metric = "tps_variance"
            operator = "greater_than"
            threshold = 0.2
            severity = "WARNING"
            cooldown_minutes = 15
            channels = @("console")
            message = "TPS variance of {{value}} indicates load imbalance"
        }
        @{
            name = "Cluster SIS Degradation"
            metric = "cluster_sis"
            operator = "less_than"
            threshold = 80
            severity = "CRITICAL"
            cooldown_minutes = 5
            channels = @("console", "webhook")
            message = "Cluster SIS score dropped to {{value}}"
        }
    )
    cascade_detection = @{
        enabled = $EnableCascadeDetection.IsPresent
        consecutive_failures_threshold = 3
        failure_rate_threshold = 0.5
        prediction_window_minutes = 5
    }
    maintenance_windows = @(
        # Example: @{ start = "02:00"; end = "04:00"; timezone = "UTC"; description = "Nightly maintenance" }
    )
    global_settings = @{
        default_cooldown_minutes = 15
        max_alerts_per_hour = 30
        alert_retention_days = 30
    }
    notifications = @{
        webhook_url = $WebhookUrl
        webhook_enabled = [bool]$WebhookUrl
    }
}

function Get-LatestClusterMetrics {
    <#
    .SYNOPSIS
        Reads latest aggregated cluster metrics
    #>
    $latestFile = Get-ChildItem -Path $AggregatorPath -Filter "cluster_metrics_*.json" -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    if (-not $latestFile) {
        return $null
    }
    
    return Get-Content -Path $latestFile.FullName | ConvertFrom-Json -AsHashtable
}

function Test-MaintenanceWindow {
    <#
    .SYNOPSIS
        Checks if current time is within a maintenance window
    #>
    param([hashtable]$Config)
    
    $now = Get-Date
    
    foreach ($window in $Config.maintenance_windows) {
        $start = [DateTime]::Parse($window.start)
        $end = [DateTime]::Parse($window.end)
        
        if ($now.TimeOfDay -ge $start.TimeOfDay -and $now.TimeOfDay -le $end.TimeOfDay) {
            return $true
        }
    }
    
    return $false
}

function Test-CascadeFailure {
    <#
    .SYNOPSIS
        Predicts cascade failure based on node failure patterns
    #>
    param(
        [hashtable]$Metrics,
        [hashtable]$Config
    )
    
    if (-not $Config.cascade_detection.enabled) { return $null }
    
    $nodeCount = $Metrics.cluster_stats.node_count
    $respondingCount = $Metrics.cluster_stats.responding_nodes
    $failureRate = ($nodeCount - $respondingCount) / $nodeCount
    
    if ($failureRate -ge $Config.cascade_detection.failure_rate_threshold) {
        return @{
            predicted = $true
            failure_rate = $failureRate
            affected_nodes = $nodeCount - $respondingCount
            severity = "CRITICAL"
            message = "Cascade failure predicted: $([Math]::Round($failureRate * 100, 1))% of nodes failing"
        }
    }
    
    return $null
}

function Send-ClusterAlert {
    <#
    .SYNOPSIS
        Sends cluster alert through configured channels
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
        Write-Host "`n[!] CLUSTER ALERT [$($Alert.severity)]" -ForegroundColor $severityColor -NoNewline
        Write-Host " $($Alert.name)" -ForegroundColor White
        Write-Host "    Time: $timestamp" -ForegroundColor Gray
        Write-Host "    Message: $($Alert.message)" -ForegroundColor Gray
        if ($Alert.affected_nodes) {
            Write-Host "    Affected Nodes: $($Alert.affected_nodes)" -ForegroundColor Gray
        }
    }
    
    # Webhook notification
    if ($Alert.channels -contains "webhook" -and $Config.notifications.webhook_enabled) {
        try {
            $payload = @{
                text = "RawrXD Cluster Alert: $($Alert.name)"
                severity = $Alert.severity
                message = $Alert.message
                timestamp = $timestamp
                affected_nodes = $Alert.affected_nodes
                cluster_metric = $Alert.metric
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri $Config.notifications.webhook_url -Method POST -Body $payload -ContentType "application/json" -TimeoutSec 5 | Out-Null
            Write-Host "    ✓ Webhook notification sent" -ForegroundColor Green
        }
        catch {
            Write-Host "    ✗ Webhook failed: $_" -ForegroundColor Red
        }
    }
}

function Invoke-ClusterAlertCheck {
    <#
    .SYNOPSIS
        Runs cluster-wide alert check cycle
    #>
    param([hashtable]$Config)
    
    $metrics = Get-LatestClusterMetrics
    
    if (-not $metrics) {
        Write-Host "  ! No cluster metrics available" -ForegroundColor Yellow
        return
    }
    
    # Check maintenance window
    if (Test-MaintenanceWindow -Config $Config) {
        Write-Host "  ℹ In maintenance window - suppressing alerts" -ForegroundColor Gray
        return
    }
    
    $now = Get-Date
    $stats = $metrics.cluster_stats
    
    # Check cascade failure prediction
    if ($EnableCascadeDetection) {
        $cascade = Test-CascadeFailure -Metrics $metrics -Config $Config
        if ($cascade -and $cascade.predicted) {
            $alertKey = "cascade_failure"
            $lastAlert = $script:AlertState.last_alerts[$alertKey]
            
            if (-not $lastAlert -or ($now - $lastAlert).TotalMinutes -ge 5) {
                Send-ClusterAlert -Alert $cascade -Config $Config
                $script:AlertState.last_alerts[$alertKey] = $now
                [void]$script:AlertState.alert_history.Add($cascade)
            }
        }
    }
    
    # Check cluster rules
    foreach ($rule in $Config.cluster_rules) {
        $metricValue = switch ($rule.metric) {
            "cluster_tps" { $stats.tps_avg }
            "response_rate" { ($stats.responding_nodes / $stats.node_count) * 100 }
            "tps_variance" { if ($stats.tps_std -and $stats.tps_avg) { $stats.tps_std / $stats.tps_avg } else { 0 } }
            "cluster_sis" { $stats.sis_avg }
            default { $null }
        }
        
        if ($null -eq $metricValue) { continue }
        
        $conditionMet = switch ($rule.operator) {
            "less_than" { $metricValue -lt $rule.threshold }
            "greater_than" { $metricValue -gt $rule.threshold }
            default { $false }
        }
        
        if ($conditionMet) {
            $alertKey = "$($rule.name):cluster"
            $lastAlert = $script:AlertState.last_alerts[$alertKey]
            $cooldown = $rule.cooldown_minutes
            
            if ($lastAlert -and ($now - $lastAlert).TotalMinutes -lt $cooldown) {
                continue
            }
            
            $alert = @{
                name = $rule.name
                severity = $rule.severity
                message = $rule.message.Replace("{{value}}", [Math]::Round($metricValue, 2)).Replace("{{threshold}}", $rule.threshold)
                metric = $rule.metric
                current_value = [Math]::Round($metricValue, 2)
                channels = $rule.channels
                timestamp = $now
            }
            
            Send-ClusterAlert -Alert $alert -Config $Config
            $script:AlertState.last_alerts[$alertKey] = $now
            [void]$script:AlertState.alert_history.Add($alert)
        }
    }
}

# Main execution
Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Aggregator Path: $AggregatorPath" -ForegroundColor White
Write-Host "  Check Interval: ${CheckInterval}s" -ForegroundColor White
Write-Host "  Cascade Detection: $EnableCascadeDetection" -ForegroundColor White
Write-Host "  Webhook: $(if ($WebhookUrl) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White

Write-Host "`nStarting cluster alert manager...`n" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Gray

try {
    while ($script:AlertState.running) {
        Invoke-ClusterAlertCheck -Config $defaultConfig
        
        Write-Host "  Next check in ${CheckInterval}s..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $CheckInterval
    }
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
}
finally {
    Write-Host "`nCluster alert manager stopped." -ForegroundColor Yellow
}
