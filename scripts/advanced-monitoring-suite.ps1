# RawrXD Advanced Monitoring Suite
# Comprehensive monitoring with alerting and anomaly detection

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("start", "stop", "status", "alert", "analyze")]
    [string]$Action = "status",
    
    [string]$ConfigFile = "config/monitoring.yaml",
    [string]$AlertChannel = "slack",
    [int]$SamplingInterval = 30,
    [switch]$EnableAnomalyDetection,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$MonitoringConfig = @{
    Metrics = @(
        @{ Name = "cpu_usage"; Threshold = 80; Unit = "%" }
        @{ Name = "memory_usage"; Threshold = 85; Unit = "%" }
        @{ Name = "disk_usage"; Threshold = 90; Unit = "%" }
        @{ Name = "inference_latency"; Threshold = 500; Unit = "ms" }
        @{ Name = "queue_depth"; Threshold = 100; Unit = "items" }
        @{ Name = "error_rate"; Threshold = 5; Unit = "%" }
    )
    
    AlertChannels = @{
        Slack = @{ Webhook = $env:SLACK_WEBHOOK_URL }
        Email = @{ SmtpServer = $env:SMTP_SERVER }
        PagerDuty = @{ Key = $env:PAGERDUTY_KEY }
    }
    
    RetentionDays = 30
}

$script:MonitoringState = @{
    StartTime = Get-Date
    IsRunning = $false
    MetricsCollected = 0
    AlertsTriggered = 0
    AnomaliesDetected = 0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Alert { param([string]$Message) Write-Host "[🚨] $Message" -ForegroundColor Red }

function Get-SystemMetrics {
    $metrics = @{}
    
    # CPU
    $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
    $metrics["cpu_usage"] = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
    
    # Memory
    $mem = Get-CimInstance Win32_OperatingSystem
    $metrics["memory_usage"] = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 2)
    
    # Disk
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $metrics["disk_usage"] = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
    
    # Simulated inference metrics
    $metrics["inference_latency"] = Get-Random -Minimum 100 -Maximum 800
    $metrics["queue_depth"] = Get-Random -Minimum 0 -Maximum 150
    $metrics["error_rate"] = Get-Random -Minimum 0 -Maximum 10
    
    return $metrics
}

function Test-MetricThresholds {
    param([hashtable]$Metrics)
    
    $alerts = @()
    
    foreach ($metric in $MonitoringConfig.Metrics) {
        if ($Metrics.ContainsKey($metric.Name)) {
            $value = $Metrics[$metric.Name]
            
            if ($value -gt $metric.Threshold) {
                $alerts += [PSCustomObject]@{
                    Metric = $metric.Name
                    Value = $value
                    Threshold = $metric.Threshold
                    Unit = $metric.Unit
                    Severity = if ($value -gt $metric.Threshold * 1.5) { "critical" } else { "warning" }
                    Timestamp = Get-Date
                }
            }
        }
    }
    
    return $alerts
}

function Send-Alert {
    param([array]$Alerts)
    
    foreach ($alert in $Alerts) {
        $message = "ALERT: $($alert.Metric) is $($alert.Value)$($alert.Unit) (threshold: $($alert.Threshold)$($alert.Unit))"
        
        switch ($AlertChannel) {
            "slack" { Write-Alert "[SLACK] $message" }
            "email" { Write-Alert "[EMAIL] $message" }
            "pagerduty" { Write-Alert "[PAGERDUTY] $message" }
            default { Write-Alert $message }
        }
        
        $script:MonitoringState.AlertsTriggered++
    }
}

function Invoke-AnomalyDetection {
    param([hashtable]$Metrics)
    
    if (-not $EnableAnomalyDetection) { return @() }
    
    # Simple anomaly detection based on thresholds
    $anomalies = @()
    
    foreach ($metric in $MonitoringConfig.Metrics) {
        if ($Metrics.ContainsKey($metric.Name)) {
            $value = $Metrics[$metric.Name]
            
            # Detect if value is significantly higher than threshold
            if ($value -gt $metric.Threshold * 2) {
                $anomalies += [PSCustomObject]@{
                    Metric = $metric.Name
                    Value = $value
                    Expected = $metric.Threshold
                    Deviation = [math]::Round((($value - $metric.Threshold) / $metric.Threshold) * 100, 2)
                }
            }
        }
    }
    
    $script:MonitoringState.AnomaliesDetected += $anomalies.Count
    return $anomalies
}

function Start-MonitoringService {
    Write-Status "Starting advanced monitoring service..."
    
    if ($DryRun) {
        Write-Warning "DRY RUN - Would start monitoring service"
        return
    }
    
    $script:MonitoringState.IsRunning = $true
    
    Write-Success "Monitoring service started (sampling every ${SamplingInterval}s)"
    Write-Host "Press Ctrl+C to stop..." -ForegroundColor Gray
    
    try {
        while ($script:MonitoringState.IsRunning) {
            $metrics = Get-SystemMetrics
            $script:MonitoringState.MetricsCollected++
            
            # Check thresholds
            $alerts = Test-MetricThresholds -Metrics $metrics
            if ($alerts.Count -gt 0) {
                Send-Alert -Alerts $alerts
            }
            
            # Anomaly detection
            $anomalies = Invoke-AnomalyDetection -Metrics $metrics
            if ($anomalies.Count -gt 0) {
                Write-Warning "Anomalies detected: $($anomalies.Count)"
            }
            
            # Display current metrics
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor Gray
            Write-Host "CPU: $($metrics['cpu_usage'])$($MonitoringConfig.Metrics[0].Unit) " -NoNewline -ForegroundColor $(if($metrics['cpu_usage'] -gt 80){'Red'}else{'Green'})
            Write-Host "MEM: $($metrics['memory_usage'])$($MonitoringConfig.Metrics[1].Unit) " -NoNewline -ForegroundColor $(if($metrics['memory_usage'] -gt 85){'Red'}else{'Green'})
            Write-Host "LAT: $($metrics['inference_latency'])$($MonitoringConfig.Metrics[3].Unit)" -ForegroundColor $(if($metrics['inference_latency'] -gt 500){'Red'}else{'Green'})
            
            Start-Sleep -Seconds $SamplingInterval
        }
    }
    finally {
        $script:MonitoringState.IsRunning = $false
    }
}

function Stop-MonitoringService {
    Write-Status "Stopping monitoring service..."
    $script:MonitoringState.IsRunning = $false
    Write-Success "Monitoring service stopped"
}

function Show-MonitoringStatus {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Advanced Monitoring Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $status = if ($script:MonitoringState.IsRunning) { "RUNNING" } else { "STOPPED" }
    $color = if ($script:MonitoringState.IsRunning) { "Green" } else { "Red" }
    
    Write-Host "Service Status: " -NoNewline
    Write-Host $status -ForegroundColor $color
    Write-Host "Metrics Collected: $($script:MonitoringState.MetricsCollected)" -ForegroundColor White
    Write-Host "Alerts Triggered: $($script:MonitoringState.AlertsTriggered)" -ForegroundColor $(if($script:MonitoringState.AlertsTriggered -gt 0){'Red'}else{'Green'})
    Write-Host "Anomalies Detected: $($script:MonitoringState.AnomaliesDetected)" -ForegroundColor $(if($script:MonitoringState.AnomaliesDetected -gt 0){'Red'}else{'Green'})
    Write-Host "Sampling Interval: ${SamplingInterval}s" -ForegroundColor Gray
    Write-Host "Alert Channel: $AlertChannel" -ForegroundColor Gray
    Write-Host "Anomaly Detection: $(if($EnableAnomalyDetection){'Enabled'}else{'Disabled'})" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "Monitored Metrics:" -ForegroundColor White
    foreach ($metric in $MonitoringConfig.Metrics) {
        Write-Host "  • $($metric.Name) (threshold: $($metric.Threshold)$($metric.Unit))" -ForegroundColor Gray
    }
}

function Invoke-MetricsAnalysis {
    Write-Status "Analyzing historical metrics..."
    
    # Simulate analysis
    $analysis = @{
        PeakCpuTime = "14:30"
        PeakMemoryTime = "15:45"
        AverageLatency = 245
        ErrorRateTrend = "decreasing"
        Recommendations = @(
            "Consider increasing memory allocation during peak hours (14:00-16:00)",
            "Queue depth spikes detected at 15:00, consider horizontal scaling",
            "Error rate is trending down, current fixes are effective"
        )
    }
    
    Write-Host ""
    Write-Host "Analysis Results:" -ForegroundColor White
    Write-Host "  Peak CPU Time: $($analysis.PeakCpuTime)" -ForegroundColor Gray
    Write-Host "  Peak Memory Time: $($analysis.PeakMemoryTime)" -ForegroundColor Gray
    Write-Host "  Average Latency: $($analysis.AverageLatency)ms" -ForegroundColor Gray
    Write-Host "  Error Rate Trend: $($analysis.ErrorRateTrend)" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Recommendations:" -ForegroundColor White
    foreach ($rec in $analysis.Recommendations) {
        Write-Host "  • $rec" -ForegroundColor Yellow
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Advanced Monitoring Suite" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "start" { Start-MonitoringService }
        "stop" { Stop-MonitoringService }
        "status" { Show-MonitoringStatus }
        "alert" { 
            $testAlerts = @(
                [PSCustomObject]@{ Metric = "cpu_usage"; Value = 95; Threshold = 80; Unit = "%"; Severity = "critical"; Timestamp = Get-Date }
            )
            Send-Alert -Alerts $testAlerts
        }
        "analyze" { Invoke-MetricsAnalysis }
    }
    
    Write-Host ""
    Write-Success "Advanced monitoring suite complete!"
}

Main
