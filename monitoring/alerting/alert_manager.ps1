# alert_manager.ps1
# Phase H.5 Batch 2/5: Threshold-Based Alerting System

param(
    [string]$ConfigPath = ".\alert_rules.yaml",
    [string]$WebhookUrl = $null,
    [string]$SmtpServer = $null,
    [string]$AlertLogPath = "${env:ProgramData}\RawrXD\logs\alerts.log"
)

$ErrorActionPreference = "Continue"

$AlertState = @{
    ActiveAlerts = @{}
    AlertHistory = @()
    LastCheck = $null
}

$DefaultRules = @{
    CPUHigh = @{
        Metric = "cpu_usage_percent"
        Threshold = 85
        Operator = "gt"
        Duration = 300  # 5 minutes
        Severity = "warning"
        Description = "CPU usage is high"
    }
    MemoryHigh = @{
        Metric = "memory_used_percent"
        Threshold = 90
        Operator = "gt"
        Duration = 300
        Severity = "critical"
        Description = "Memory usage is critically high"
    }
    DiskLow = @{
        Metric = "disk_free_gb"
        Threshold = 5
        Operator = "lt"
        Duration = 60
        Severity = "critical"
        Description = "Disk space is critically low"
    }
    ServiceDown = @{
        Metric = "service_status"
        Threshold = 1
        Operator = "lt"
        Duration = 30
        Severity = "critical"
        Description = "RawrXD service is not running"
    }
    InferenceLatency = @{
        Metric = "inference_latency_ms"
        Threshold = 1000
        Operator = "gt"
        Duration = 180
        Severity = "warning"
        Description = "Inference latency is elevated"
    }
    LowTPS = @{
        Metric = "inference_tps"
        Threshold = 10
        Operator = "lt"
        Duration = 300
        Severity = "warning"
        Description = "TPS is below target"
    }
}

function Write-AlertLog($Message, $Severity = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Severity] $Message"
    
    # Write to console
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
    
    # Write to file
    $logEntry | Out-File $AlertLogPath -Append
}

function Test-AlertCondition($Rule, $Value) {
    switch ($Rule.Operator) {
        "gt" { return $Value -gt $Rule.Threshold }
        "lt" { return $Value -lt $Rule.Threshold }
        "eq" { return $Value -eq $Rule.Threshold }
        "ne" { return $Value -ne $Rule.Threshold }
        default { return $false }
    }
}

function Send-AlertNotification($Alert) {
    $message = @"
ALERT: $($Alert.Name)
Severity: $($Alert.Severity)
Time: $($Alert.Timestamp)
Description: $($Alert.Description)
Current Value: $($Alert.Value)
Threshold: $($Alert.Threshold)

Instance: $($env:COMPUTERNAME)
"@
    
    # Webhook notification
    if ($WebhookUrl) {
        try {
            $payload = @{
                text = $message
                severity = $Alert.Severity
                alert_name = $Alert.Name
                timestamp = $Alert.Timestamp
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 10
            Write-AlertLog "Webhook notification sent for $($Alert.Name)" "INFO"
        }
        catch {
            Write-AlertLog "Failed to send webhook: $_" "WARNING"
        }
    }
    
    # Email notification (if SMTP configured)
    if ($SmtpServer) {
        # Email sending logic would go here
        Write-AlertLog "Email notification would be sent via $SmtpServer" "INFO"
    }
    
    # Windows Event Log
    $eventLevel = switch ($Alert.Severity) {
        "critical" { "Error" }
        "warning" { "Warning" }
        default { "Information" }
    }
    
    Write-EventLog -LogName "Application" -Source "RawrXD" -EventId 1001 -EntryType $eventLevel -Message $message -ErrorAction SilentlyContinue
}

function Send-AlertResolved($Alert) {
    $message = @"
RESOLVED: $($Alert.Name)
Severity: $($Alert.Severity)
Time Resolved: $(Get-Date -Format "o")
Duration: $([math]::Round(((Get-Date) - $Alert.StartTime).TotalMinutes, 2)) minutes

Instance: $($env:COMPUTERNAME)
"@
    
    if ($WebhookUrl) {
        try {
            $payload = @{
                text = $message
                severity = "resolved"
                alert_name = $Alert.Name
                timestamp = Get-Date -Format "o"
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 10
        }
        catch {
            Write-AlertLog "Failed to send resolution webhook: $_" "WARNING"
        }
    }
    
    Write-AlertLog "Alert resolved: $($Alert.Name)" "INFO"
}

function Invoke-AlertCheck {
    # Get current metrics
    $metricsFile = Join-Path $env:ProgramData "RawrXD\metrics\current.json"
    if (-not (Test-Path $metricsFile)) {
        return
    }
    
    $metrics = Get-Content $metricsFile | ConvertFrom-Json
    $currentTime = Get-Date
    
    foreach ($rule in $DefaultRules.GetEnumerator()) {
        $ruleName = $rule.Key
        $ruleConfig = $rule.Value
        
        # Get metric value
        $metricValue = $metrics.$($ruleConfig.Metric)
        if ($null -eq $metricValue) {
            continue
        }
        
        # Check condition
        $isTriggered = Test-AlertCondition -Rule $ruleConfig -Value $metricValue
        
        if ($isTriggered) {
            # Check if alert already active
            if (-not $AlertState.ActiveAlerts.ContainsKey($ruleName)) {
                # New alert
                $AlertState.ActiveAlerts[$ruleName] = @{
                    Name = $ruleName
                    Severity = $ruleConfig.Severity
                    Description = $ruleConfig.Description
                    StartTime = $currentTime
                    Value = $metricValue
                    Threshold = $ruleConfig.Threshold
                    Timestamp = $currentTime.ToString("o")
                }
                
                Write-AlertLog "ALERT TRIGGERED: $ruleName - $($ruleConfig.Description) (Value: $metricValue, Threshold: $($ruleConfig.Threshold))" $ruleConfig.Severity.ToUpper()
                Send-AlertNotification -Alert $AlertState.ActiveAlerts[$ruleName]
            }
        }
        else {
            # Check if alert was active and now resolved
            if ($AlertState.ActiveAlerts.ContainsKey($ruleName)) {
                $resolvedAlert = $AlertState.ActiveAlerts[$ruleName]
                $AlertState.ActiveAlerts.Remove($ruleName)
                
                Write-AlertLog "ALERT RESOLVED: $ruleName" "INFO"
                Send-AlertResolved -Alert $resolvedAlert
            }
        }
    }
    
    $AlertState.LastCheck = $currentTime
}

function Start-AlertManager {
    Write-AlertLog "Starting RawrXD Alert Manager"
    Write-AlertLog "Monitoring $($DefaultRules.Count) alert rules"
    Write-AlertLog "Webhook: $(if ($WebhookUrl) { 'Enabled' } else { 'Disabled' })"
    Write-AlertLog ""
    
    # Create event log source if needed
    if (-not [System.Diagnostics.EventLog]::SourceExists("RawrXD")) {
        New-EventLog -LogName "Application" -Source "RawrXD" -ErrorAction SilentlyContinue
    }
    
    while ($true) {
        Invoke-AlertCheck
        Start-Sleep -Seconds 30
    }
}

# Main execution
Start-AlertManager
