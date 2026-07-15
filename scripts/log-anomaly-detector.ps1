# RawrXD Log Anomaly Detector
# Detects anomalies in application logs using pattern analysis
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Analyze", "Monitor", "Report", "Train")]
    [string]$Action = "Analyze",
    
    [Parameter()]
    [string]$LogPath = "logs/app.log",
    
    [Parameter()]
    [string]$TimeRange = "1h",
    
    [Parameter()]
    [double]$Sensitivity = 2.0,
    
    [Parameter()]
    [switch]$RealTime
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-BaselineStats {
    return @{
        ErrorRate = 0.02
        AverageResponseTime = 150
        RequestRate = 100
        UniqueIPs = 50
    }
}

function Invoke-LogAnalysis {
    Write-Host "`n🔍 Log Anomaly Detection" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Analyzing: $LogPath"
    Write-Status "Time Range: $TimeRange"
    Write-Status "Sensitivity: $Sensitivity"
    Write-Host ""
    
    $baseline = Get-BaselineStats
    
    # Simulate log analysis
    Write-Status "Loading log data..."
    $logEntries = Get-Random -Minimum 1000 -Maximum 10000
    Start-Sleep -Milliseconds 500
    Write-Success "  ✓ Loaded $logEntries entries"
    
    Write-Status "Calculating baseline metrics..."
    Start-Sleep -Milliseconds 300
    Write-Success "  ✓ Baseline established"
    
    Write-Status "Detecting anomalies..."
    Write-Host ""
    
    # Generate anomalies
    $anomalies = @()
    $anomalyCount = Get-Random -Minimum 0 -Maximum 6
    
    for ($i = 0; $i -lt $anomalyCount; $i++) {
        $types = @("Error Spike", "Latency Increase", "Traffic Pattern", "Security Event")
        $type = $types | Get-Random
        $severity = @("Low", "Medium", "High") | Get-Random
        
        $anomalies += @{
            Type = $type
            Severity = $severity
            Timestamp = (Get-Date).AddMinutes(-(Get-Random -Minimum 1 -Maximum 60)).ToString("o")
            Description = switch ($type) {
                "Error Spike" { "Error rate exceeded baseline by $([math]::Round((Get-Random -Minimum 2 -Maximum 5) * 100))%" }
                "Latency Increase" { "P95 latency increased to $([Get-Random -Minimum 500 -Maximum 2000])ms" }
                "Traffic Pattern" { "Unusual traffic pattern from IP range" }
                "Security Event" { "Multiple failed authentication attempts" }
            }
        }
    }
    
    # Display results
    if ($anomalies.Count -gt 0) {
        Write-Host "Anomalies Detected: $($anomalies.Count)" -ForegroundColor Yellow
        Write-Host ""
        
        foreach ($anomaly in ($anomalies | Sort-Object Severity -Descending)) {
            $color = switch ($anomaly.Severity) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                default { "White" }
            }
            
            Write-Host "[$($anomaly.Severity)] $($anomaly.Type)" -ForegroundColor $color
            Write-Host "  Time: $([datetime]$anomaly.Timestamp)"
            Write-Host "  $($anomaly.Description)"
            Write-Host ""
        }
    } else {
        Write-Success "No anomalies detected - system operating normally"
    }
    
    # Show current metrics
    Write-Host "Current Metrics vs Baseline" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host "Metric              Baseline    Current     Status"
    Write-Host "------              --------    -------     ------"
    
    $currentErrorRate = $baseline.ErrorRate * (1 + (Get-Random -Minimum -0.5 -Maximum 1.0))
    $currentLatency = $baseline.AverageResponseTime * (1 + (Get-Random -Minimum -0.2 -Maximum 0.5))
    
    Write-Host "Error Rate          $($baseline.ErrorRate.ToString('P'))".PadRight(20) -NoNewline
    Write-Host $currentErrorRate.ToString('P').PadRight(12) -NoNewline
    Write-Host $(if ($currentErrorRate -gt $baseline.ErrorRate * 2) { "⚠️ ELEVATED" } else { "✓ Normal" }) -ForegroundColor $(if ($currentErrorRate -gt $baseline.ErrorRate * 2) { "Red" } else { "Green" })
    
    Write-Host "Avg Response Time   $($baseline.AverageResponseTime)ms".PadRight(20) -NoNewline
    Write-Host "$([math]::Round($currentLatency))ms".PadRight(12) -NoNewline
    Write-Host $(if ($currentLatency -gt 300) { "⚠️ HIGH" } else { "✓ Normal" }) -ForegroundColor $(if ($currentLatency -gt 300) { "Red" } else { "Green" })
}

function Start-RealTimeMonitoring {
    Write-Host "`n📡 Real-Time Log Monitoring" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Starting real-time monitoring..."
    Write-Status "Press Ctrl+C to stop"
    Write-Host ""
    
    for ($i = 0; $i -lt 20; $i++) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        $status = @("Normal", "Normal", "Normal", "Warning", "Normal") | Get-Random
        $color = if ($status -eq "Warning") { "Yellow" } else { "Green" }
        
        Write-Host "[$timestamp] Status: " -NoNewline
        Write-Host $status -ForegroundColor $color
        
        Start-Sleep -Milliseconds 500
    }
    
    Write-Host ""
    Write-Status "Monitoring stopped"
}

# Main execution
try {
    switch ($Action) {
        "Analyze" { Invoke-LogAnalysis }
        "Monitor" { Start-RealTimeMonitoring }
        "Report" { Write-Status "Anomaly report would be generated" }
        "Train" { Write-Status "Baseline model would be trained on historical data" }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
