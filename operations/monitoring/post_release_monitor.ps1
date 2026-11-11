# RawrXD Post-Release Monitor
# Phase J Batch 1/5: Post-Release System Monitoring
# Monitors the released system for issues and performance

param(
    [Parameter()]
    [switch]$Daemon,
    
    [Parameter()]
    [int]$MonitorIntervalSeconds = 60,
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\operations",
    
    [Parameter()]
    [string]$StatePath = "$PSScriptRoot\monitor_state",
    
    [Parameter()]
    [ValidateSet("Minimal", "Standard", "Verbose")]
    [string]$MonitorLevel = "Standard",
    
    [Parameter()]
    [switch]$ShowStatus
)

# Monitoring configuration
$MonitorConfig = @{
    Metrics = @{
        CPU = @{ Warning = 70; Critical = 90 }
        Memory = @{ Warning = 80; Critical = 95 }
        Disk = @{ Warning = 85; Critical = 95 }
        TPS = @{ Warning = 25; Critical = 15 }
        Latency = @{ Warning = 100; Critical = 200 }
    }
    
    Services = @(
        "RawrXD_Runtime",
        "RawrXD_Telemetry",
        "RawrXD_Monitor"
    )
    
    Processes = @(
        "rawrxd",
        "llama-server"
    )
    
    RetentionHours = 168  # 7 days
}

# Ensure directories exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
if (-not (Test-Path $StatePath)) {
    New-Item -ItemType Directory -Path $StatePath -Force | Out-Null
}

# State file
$StateFile = Join-Path $StatePath "monitor_state.json"

function Write-MonitorLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "post_release_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "ALERT" { "Magenta" }
        "MONITOR" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-MonitorState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalChecks = 0
        Alerts = @()
        Metrics = @{}
        ServiceStatus = @{}
        LastCheck = $null
    }
}

function Save-MonitorState {
    param($State)
    $State.LastCheck = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Get-SystemMetrics {
    $metrics = @{}
    
    # CPU usage
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        if ($cpu) {
            $metrics.CPU = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
        }
    }
    catch {
        $metrics.CPU = -1
    }
    
    # Memory usage
    try {
        $memory = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($memory) {
            $metrics.Memory = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
        }
    }
    catch {
        $metrics.Memory = -1
    }
    
    # Disk usage
    try {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($disk) {
            $metrics.Disk = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
        }
    }
    catch {
        $metrics.Disk = -1
    }
    
    # Process metrics (if running)
    $rawrxdProcess = Get-Process -Name "rawrxd" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($rawrxdProcess) {
        $metrics.ProcessCPU = [math]::Round($rawrxdProcess.CPU, 2)
        $metrics.ProcessMemory = [math]::Round($rawrxdProcess.WorkingSet64 / 1MB, 2)
    }
    
    return $metrics
}

function Get-ServiceStatus {
    $status = @{}
    
    foreach ($service in $MonitorConfig.Services) {
        try {
            $svc = Get-Service $service -ErrorAction SilentlyContinue
            if ($svc) {
                $status[$service] = $svc.Status.ToString()
            }
            else {
                $status[$service] = "NotInstalled"
            }
        }
        catch {
            $status[$service] = "Unknown"
        }
    }
    
    return $status
}

function Test-MetricThresholds {
    param([hashtable]$Metrics)
    
    $alerts = @()
    
    foreach ($metricName in $Metrics.Keys) {
        $value = $Metrics[$metricName]
        if ($value -eq -1) { continue }
        
        if ($MonitorConfig.Metrics.ContainsKey($metricName)) {
            $thresholds = $MonitorConfig.Metrics[$metricName]
            
            if ($metricName -in @("TPS")) {
                # Lower is worse for TPS
                if ($value -le $thresholds.Critical) {
                    $alerts += @{
                        Metric = $metricName
                        Value = $value
                        Severity = "Critical"
                        Message = "$metricName critically low: $value"
                    }
                }
                elseif ($value -le $thresholds.Warning) {
                    $alerts += @{
                        Metric = $metricName
                        Value = $value
                        Severity = "Warning"
                        Message = "$metricName below threshold: $value"
                    }
                }
            }
            else {
                # Higher is worse for CPU, Memory, Disk
                if ($value -ge $thresholds.Critical) {
                    $alerts += @{
                        Metric = $metricName
                        Value = $value
                        Severity = "Critical"
                        Message = "$metricName critically high: $value%"
                    }
                }
                elseif ($value -ge $thresholds.Warning) {
                    $alerts += @{
                        Metric = $metricName
                        Value = $value
                        Severity = "Warning"
                        Message = "$metricName above threshold: $value%"
                    }
                }
            }
        }
    }
    
    return $alerts
}

function Test-ServiceHealth {
    param([hashtable]$ServiceStatus)
    
    $alerts = @()
    
    foreach ($service in $ServiceStatus.Keys) {
        $status = $ServiceStatus[$service]
        
        if ($status -ne "Running" -and $status -ne "NotInstalled") {
            $alerts += @{
                Service = $service
                Status = $status
                Severity = if ($status -eq "Stopped") { "Critical" } else { "Warning" }
                Message = "Service $service is $status"
            }
        }
    }
    
    return $alerts
}

function Invoke-MonitoringCycle {
    $state = Get-MonitorState
    $state.TotalChecks++
    
    # Gather metrics
    $metrics = Get-SystemMetrics
    $state.Metrics = $metrics
    
    # Check service status
    $serviceStatus = Get-ServiceStatus
    $state.ServiceStatus = $serviceStatus
    
    # Test thresholds
    $metricAlerts = Test-MetricThresholds -Metrics $metrics
    $serviceAlerts = Test-ServiceHealth -ServiceStatus $serviceStatus
    
    $allAlerts = $metricAlerts + $serviceAlerts
    
    # Log alerts
    foreach ($alert in $allAlerts) {
        $state.Alerts += $alert
        Write-MonitorLog $alert.Message $alert.Severity
        
        # Keep only last 100 alerts
        if ($state.Alerts.Count -gt 100) {
            $state.Alerts = $state.Alerts | Select-Object -Last 100
        }
    }
    
    # Log status based on monitor level
    switch ($MonitorLevel) {
        "Minimal" {
            if ($allAlerts.Count -gt 0) {
                Write-MonitorLog "Check $($state.TotalChecks): $($allAlerts.Count) alerts" "MONITOR"
            }
        }
        "Standard" {
            Write-MonitorLog "Check $($state.TotalChecks): CPU $($metrics.CPU)%, Memory $($metrics.Memory)%, Alerts: $($allAlerts.Count)" "MONITOR"
        }
        "Verbose" {
            Write-MonitorLog "Check $($state.TotalChecks):" "MONITOR"
            Write-MonitorLog "  CPU: $($metrics.CPU)%, Memory: $($metrics.Memory)%, Disk: $($metrics.Disk)%" "INFO"
            Write-MonitorLog "  Services: $($serviceStatus.Count) checked" "INFO"
            Write-MonitorLog "  Alerts: $($allAlerts.Count)" "INFO"
        }
    }
    
    Save-MonitorState -State $state
    
    return @{
        Metrics = $metrics
        Alerts = $allAlerts
        AlertCount = $allAlerts.Count
    }
}

function Show-MonitorStatus {
    $state = Get-MonitorState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Post-Release Monitor Status                    ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Started: $($state.StartTime)" -ForegroundColor Cyan
    Write-Host "║ Total Checks: $($state.TotalChecks)" -ForegroundColor Cyan
    Write-Host "║ Last Check: $($state.LastCheck)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($state.Metrics.Count -gt 0) {
        Write-Host "║ Current Metrics:" -ForegroundColor Cyan
        foreach ($metric in $state.Metrics.Keys) {
            $value = $state.Metrics[$metric]
            $color = "White"
            if ($MonitorConfig.Metrics.ContainsKey($metric)) {
                $thresholds = $MonitorConfig.Metrics[$metric]
                if ($value -ge $thresholds.Critical) { $color = "Red" }
                elseif ($value -ge $thresholds.Warning) { $color = "Yellow" }
                else { $color = "Green" }
            }
            Write-Host "║   $metric`: $value" -ForegroundColor $color
        }
    }
    
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Service Status:" -ForegroundColor Cyan
    foreach ($service in $state.ServiceStatus.Keys) {
        $status = $state.ServiceStatus[$service]
        $color = switch ($status) {
            "Running" { "Green" }
            "Stopped" { "Red" }
            default { "Yellow" }
        }
        Write-Host "║   $service`: $status" -ForegroundColor $color
    }
    
    $recentAlerts = ($state.Alerts | Select-Object -Last 5)
    if ($recentAlerts.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Recent Alerts:" -ForegroundColor Yellow
        foreach ($alert in $recentAlerts) {
            $color = if ($alert.Severity -eq "Critical") { "Red" } else { "Yellow" }
            Write-Host "║   [$($alert.Severity)] $($alert.Message)" -ForegroundColor $color
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
if ($ShowStatus) {
    Show-MonitorStatus
    exit 0
}

Write-MonitorLog "RawrXD Post-Release Monitor Started" "MONITOR"
Write-MonitorLog "Monitor Level: $MonitorLevel" "INFO"
Write-MonitorLog "Interval: $MonitorIntervalSeconds seconds" "INFO"

if ($Daemon) {
    Write-MonitorLog "Running in daemon mode..." "MONITOR"
    while ($true) {
        Invoke-MonitoringCycle
        Start-Sleep -Seconds $MonitorIntervalSeconds
    }
}
else {
    Write-MonitorLog "Running single monitoring cycle..." "MONITOR"
    $result = Invoke-MonitoringCycle
    Write-MonitorLog "Monitoring cycle complete. Alerts: $($result.AlertCount)" "INFO"
}
