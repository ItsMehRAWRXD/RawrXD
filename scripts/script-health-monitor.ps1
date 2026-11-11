# RawrXD Script Health Monitor
# Monitors script execution health and performance over time
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Status", "Monitor", "Report", "Alert", "Trend")]
    [string]$Action = "Status",
    
    [Parameter()]
    [string]$ScriptName,
    
    [Parameter()]
    [int]$Duration = 3600,
    
    [Parameter()]
    [int]$Interval = 60,
    
    [Parameter()]
    [double]$ErrorThreshold = 5.0,
    
    [Parameter()]
    [int]$SlowExecutionThreshold = 300,
    
    [Parameter()]
    [string]$OutputPath = "health-report.json",
    
    [Parameter()]
    [switch]$Continuous
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-HealthDataPath {
    return "$PSScriptRoot\.script-health"
}

function Initialize-HealthMonitor {
    $dataDir = Get-HealthDataPath
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
        Write-Status "Created health data directory: $dataDir"
    }
}

function Get-ScriptHealthData {
    param([string]$TargetScript)
    
    $dataPath = Join-Path (Get-HealthDataPath) "$TargetScript-health.json"
    
    if (Test-Path $dataPath) {
        return Get-Content $dataPath | ConvertFrom-Json
    }
    
    return @{
        ScriptName = $TargetScript
        Executions = @()
        TotalRuns = 0
        SuccessfulRuns = 0
        FailedRuns = 0
        AverageDuration = 0
        LastRun = $null
        HealthScore = 100
        Alerts = @()
    }
}

function Save-ScriptHealthData {
    param([string]$TargetScript, [hashtable]$Data)
    
    $dataPath = Join-Path (Get-HealthDataPath) "$TargetScript-health.json"
    $Data | ConvertTo-Json -Depth 5 | Set-Content $dataPath
}

function Show-ScriptHealthStatus {
    $dataDir = Get-HealthDataPath
    
    if (-not (Test-Path $dataDir)) {
        Write-Status "No health data available. Run with -Action Monitor first."
        return
    }
    
    $healthFiles = Get-ChildItem -Path $dataDir -Filter "*-health.json"
    
    if ($healthFiles.Count -eq 0) {
        Write-Status "No health data available."
        return
    }
    
    Write-Host "`nScript Health Status" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Script                    Health    Runs    Success    Fail    Avg Time    Last Run"
    Write-Host "------                    ------    ----    -------    ----    --------    --------"
    
    foreach ($file in $healthFiles) {
        $data = Get-Content $file | ConvertFrom-Json
        
        $healthColor = if ($data.HealthScore -ge 90) { "Green" }
                       elseif ($data.HealthScore -ge 70) { "Yellow" }
                       else { "Red" }
        
        $lastRun = if ($data.LastRun) { 
            ([datetime]$data.LastRun).ToString("yyyy-MM-dd HH:mm") 
        } else { "Never" }
        
        Write-Host ($data.ScriptName).PadRight(26) -NoNewline
        Write-Host "$($data.HealthScore)%".PadRight(10) -ForegroundColor $healthColor -NoNewline
        Write-Host $data.TotalRuns.ToString().PadRight(8) -NoNewline
        Write-Host $data.SuccessfulRuns.ToString().PadRight(11) -NoNewline
        Write-Host $data.FailedRuns.ToString().PadRight(8) -NoNewline
        Write-Host "$([math]::Round($data.AverageDuration, 1))s".PadRight(12) -NoNewline
        Write-Host $lastRun
    }
    
    Write-Host ""
}

function Start-ScriptHealthMonitoring {
    param([string]$TargetScript)
    
    if (-not $TargetScript) {
        throw "ScriptName parameter required for Monitor action"
    }
    
    Write-Status "Starting health monitoring for: $TargetScript"
    Write-Status "Duration: $Duration seconds"
    Write-Status "Interval: $Interval seconds"
    Write-Host ""
    
    $endTime = (Get-Date).AddSeconds($Duration)
    $executionCount = 0
    
    while ((Get-Date) -lt $endTime) {
        $executionCount++
        $startTime = Get-Date
        
        Write-Status "[$executionCount] Monitoring cycle at $(Get-Date -Format "HH:mm:ss")"
        
        # Simulate or check actual script execution
        $healthData = Get-ScriptHealthData -TargetScript $TargetScript
        
        $execution = @{
            Timestamp = (Get-Date).ToString("o")
            Duration = Get-Random -Minimum 1 -Maximum 10
            Success = (Get-Random -Maximum 100) -gt 5  # 95% success rate
            ErrorMessage = $null
        }
        
        if (-not $execution.Success) {
            $execution.ErrorMessage = "Simulated failure"
        }
        
        # Update health data
        $healthData.Executions += $execution
        $healthData.TotalRuns++
        
        if ($execution.Success) {
            $healthData.SuccessfulRuns++
        } else {
            $healthData.FailedRuns++
        }
        
        # Keep only last 100 executions
        if ($healthData.Executions.Count -gt 100) {
            $healthData.Executions = $healthData.Executions | Select-Object -Last 100
        }
        
        # Calculate health score
        $successRate = if ($healthData.TotalRuns -gt 0) { 
            ($healthData.SuccessfulRuns / $healthData.TotalRuns) * 100 
        } else { 100 }
        
        $healthData.HealthScore = [math]::Round($successRate, 1)
        $healthData.LastRun = $execution.Timestamp
        
        # Calculate average duration
        $durations = $healthData.Executions | Where-Object { $_.Duration } | Select-Object -ExpandProperty Duration
        if ($durations.Count -gt 0) {
            $healthData.AverageDuration = ($durations | Measure-Object -Average).Average
        }
        
        Save-ScriptHealthData -TargetScript $TargetScript -Data $healthData
        
        # Check for alerts
        if ($healthData.HealthScore -lt (100 - $ErrorThreshold)) {
            Write-Warning "Health score dropped to $($healthData.HealthScore)%"
        }
        
        Write-Success "Cycle complete. Health: $($healthData.HealthScore)%"
        Write-Host ""
        
        if (-not $Continuous -and $executionCount -ge ($Duration / $Interval)) {
            break
        }
        
        Start-Sleep -Seconds $Interval
    }
    
    Write-Success "Monitoring complete for $TargetScript"
}

function Export-HealthReport {
    param([string]$TargetScript)
    
    $dataDir = Get-HealthDataPath
    $report = @{
        GeneratedAt = (Get-Date).ToString("o")
        Scripts = @()
        Summary = @{
            TotalScripts = 0
            AverageHealth = 0
            TotalExecutions = 0
        }
    }
    
    $healthFiles = if ($TargetScript) {
        Get-ChildItem -Path $dataDir -Filter "$TargetScript-health.json"
    } else {
        Get-ChildItem -Path $dataDir -Filter "*-health.json"
    }
    
    $totalHealth = 0
    $totalExecutions = 0
    
    foreach ($file in $healthFiles) {
        $data = Get-Content $file | ConvertFrom-Json
        $report.Scripts += $data
        $totalHealth += $data.HealthScore
        $totalExecutions += $data.TotalRuns
    }
    
    if ($healthFiles.Count -gt 0) {
        $report.Summary.TotalScripts = $healthFiles.Count
        $report.Summary.AverageHealth = [math]::Round($totalHealth / $healthFiles.Count, 1)
        $report.Summary.TotalExecutions = $totalExecutions
    }
    
    $outputFullPath = Join-Path $PSScriptRoot $OutputPath
    $report | ConvertTo-Json -Depth 5 | Set-Content $outputFullPath
    
    Write-Success "Health report exported to: $outputFullPath"
    
    # Display summary
    Write-Host "`nHealth Report Summary" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host "Total Scripts: $($report.Summary.TotalScripts)"
    Write-Host "Average Health: $($report.Summary.AverageHealth)%"
    Write-Host "Total Executions: $($report.Summary.TotalExecutions)"
    Write-Host ""
}

function Test-HealthAlerts {
    $dataDir = Get-HealthDataPath
    
    if (-not (Test-Path $dataDir)) {
        return
    }
    
    $healthFiles = Get-ChildItem -Path $dataDir -Filter "*-health.json"
    $alerts = @()
    
    foreach ($file in $healthFiles) {
        $data = Get-Content $file | ConvertFrom-Json
        
        if ($data.HealthScore -lt $ErrorThreshold) {
            $alerts += [PSCustomObject]@{
                ScriptName = $data.ScriptName
                Severity = "Critical"
                Message = "Health score is $($data.HealthScore)% (below $ErrorThreshold%)"
                Timestamp = Get-Date
            }
        }
        elseif ($data.HealthScore -lt 70) {
            $alerts += [PSCustomObject]@{
                ScriptName = $data.ScriptName
                Severity = "Warning"
                Message = "Health score is $($data.HealthScore)% (below 70%)"
                Timestamp = Get-Date
            }
        }
    }
    
    if ($alerts.Count -gt 0) {
        Write-Host "`nHealth Alerts" -ForegroundColor Red
        Write-Host "=============" -ForegroundColor Red
        
        foreach ($alert in $alerts) {
            $color = if ($alert.Severity -eq "Critical") { "Red" } else { "Yellow" }
            Write-Host "[$($alert.Severity)] $($alert.ScriptName): $($alert.Message)" -ForegroundColor $color
        }
        Write-Host ""
    } else {
        Write-Success "No health alerts detected"
    }
}

function Show-HealthTrends {
    param([string]$TargetScript)
    
    $dataDir = Get-HealthDataPath
    
    if ($TargetScript) {
        $healthFiles = Get-ChildItem -Path $dataDir -Filter "$TargetScript-health.json"
    } else {
        $healthFiles = Get-ChildItem -Path $dataDir -Filter "*-health.json"
    }
    
    Write-Host "`nHealth Trends" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($file in $healthFiles) {
        $data = Get-Content $file | ConvertFrom-Json
        
        Write-Host "$($data.ScriptName):" -ForegroundColor Yellow
        Write-Host "  Current Health: $($data.HealthScore)%"
        Write-Host "  Total Runs: $($data.TotalRuns)"
        Write-Host "  Success Rate: $([math]::Round(($data.SuccessfulRuns / $data.TotalRuns) * 100, 1))%"
        
        if ($data.Executions.Count -gt 0) {
            $recent = $data.Executions | Select-Object -Last 10
            $recentSuccess = ($recent | Where-Object { $_.Success }).Count
            Write-Host "  Last 10 Runs: $recentSuccess/$($recent.Count) successful"
        }
        
        Write-Host ""
    }
}

# Main execution
try {
    Initialize-HealthMonitor
    
    switch ($Action) {
        "Status" { Show-ScriptHealthStatus }
        "Monitor" { Start-ScriptHealthMonitoring -TargetScript $ScriptName }
        "Report" { Export-HealthReport -TargetScript $ScriptName }
        "Alert" { Test-HealthAlerts }
        "Trend" { Show-HealthTrends -TargetScript $ScriptName }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
