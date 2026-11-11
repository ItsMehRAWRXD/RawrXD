# health_check.ps1
# Phase H.4 Batch 4/5: Pre/Post Rollback Health Validation

param(
    [string]$Mode = "full",
    [string]$InstallDir = "${env:ProgramFiles}\RawrXD",
    [string]$OutputFormat = "console",
    [string]$OutputFile = $null
)

$ErrorActionPreference = "Stop"

$HealthThresholds = @{
    MinDiskSpaceGB = 5
    MaxMemoryUsagePercent = 90
    MaxCPUTempCelsius = 85
    ServiceResponseTimeMs = 5000
    MinTPS = 10
}

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-ServiceHealth {
    Write-Log "Checking service health..."
    
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    if (-not $service) {
        return @{ Status = "FAIL"; Message = "Service not found"; Details = $null }
    }
    
    if ($service.Status -ne "Running") {
        return @{ Status = "FAIL"; Message = "Service not running"; Details = $service.Status }
    }
    
    # Check process
    $process = Get-Process -Name "RawrXD" -ErrorAction SilentlyContinue
    if (-not $process) {
        return @{ Status = "FAIL"; Message = "Process not found"; Details = $null }
    }
    
    return @{ 
        Status = "PASS"; 
        Message = "Service healthy"; 
        Details = @{
            PID = $process.Id
            MemoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
            CPU = $process.CPU
        }
    }
}

function Test-SystemResources {
    Write-Log "Checking system resources..."
    
    $results = @()
    
    # Disk space
    $disk = Get-PSDrive -Name C
    $freeGB = [math]::Round($disk.Free / 1GB, 2)
    if ($freeGB -lt $HealthThresholds.MinDiskSpaceGB) {
        $results += @{ Component = "Disk"; Status = "FAIL"; Message = "Low disk space: $freeGB GB" }
    }
    else {
        $results += @{ Component = "Disk"; Status = "PASS"; Message = "Disk space OK: $freeGB GB free" }
    }
    
    # Memory
    $memory = Get-CimInstance -ClassName Win32_OperatingSystem
    $memoryUsedPercent = (($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100
    if ($memoryUsedPercent -gt $HealthThresholds.MaxMemoryUsagePercent) {
        $results += @{ Component = "Memory"; Status = "WARN"; Message = "High memory usage: $([math]::Round($memoryUsedPercent, 1))%" }
    }
    else {
        $results += @{ Component = "Memory"; Status = "PASS"; Message = "Memory OK: $([math]::Round($memoryUsedPercent, 1))% used" }
    }
    
    return $results
}

function Test-ConfigurationHealth {
    Write-Log "Checking configuration health..."
    
    $configPath = Join-Path $InstallDir "config\rawrxd.yaml"
    if (-not (Test-Path $configPath)) {
        return @{ Status = "FAIL"; Message = "Configuration file missing"; Details = $null }
    }
    
    try {
        $config = Get-Content $configPath -Raw
        # Basic YAML validation
        if ($config -match "version:" -and $config -match "server:") {
            return @{ Status = "PASS"; Message = "Configuration valid"; Details = @{ Path = $configPath } }
        }
        else {
            return @{ Status = "FAIL"; Message = "Configuration incomplete"; Details = $null }
        }
    }
    catch {
        return @{ Status = "FAIL"; Message = "Configuration parse error"; Details = $_.Exception.Message }
    }
}

function Test-NetworkConnectivity {
    Write-Log "Checking network connectivity..."
    
    $endpoints = @(
        @{ Name = "API"; Url = "http://localhost:8080/health" },
        @{ Name = "GitHub"; Url = "https://github.com" },
        @{ Name = "RawrXD"; Url = "https://rawrxd.ai" }
    )
    
    $results = @()
    foreach ($endpoint in $endpoints) {
        try {
            $response = Invoke-WebRequest -Uri $endpoint.Url -TimeoutSec 5 -ErrorAction Stop
            $results += @{ 
                Component = $endpoint.Name; 
                Status = "PASS"; 
                Message = "Connected ($($response.StatusCode))" 
            }
        }
        catch {
            $results += @{ 
                Component = $endpoint.Name; 
                Status = "WARN"; 
                Message = "Connection failed" 
            }
        }
    }
    
    return $results
}

function Test-Performance {
    Write-Log "Checking performance metrics..."
    
    # Check if we can get metrics from the service
    try {
        $metrics = Invoke-RestMethod -Uri "http://localhost:8080/metrics" -TimeoutSec 5 -ErrorAction Stop
        
        $results = @()
        
        if ($metrics.tps -lt $HealthThresholds.MinTPS) {
            $results += @{ Component = "TPS"; Status = "WARN"; Message = "Low TPS: $($metrics.tps)" }
        }
        else {
            $results += @{ Component = "TPS"; Status = "PASS"; Message = "TPS OK: $($metrics.tps)" }
        }
        
        if ($metrics.latency_p95 -gt 100) {
            $results += @{ Component = "Latency"; Status = "WARN"; Message = "High latency: $($metrics.latency_p95)ms" }
        }
        else {
            $results += @{ Component = "Latency"; Status = "PASS"; Message = "Latency OK: $($metrics.latency_p95)ms" }
        }
        
        return $results
    }
    catch {
        return @{ Component = "Performance"; Status = "WARN"; Message = "Cannot retrieve metrics" }
    }
}

function Invoke-FullHealthCheck {
    Write-Log "Starting full health check..."
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Mode = $Mode
        OverallStatus = "UNKNOWN"
        Checks = @()
        Summary = @{}
    }
    
    $passCount = 0
    $warnCount = 0
    $failCount = 0
    
    # Run all checks
    $checks = @()
    
    # Service health
    $serviceResult = Test-ServiceHealth
    $checks += $serviceResult
    switch ($serviceResult.Status) {
        "PASS" { $passCount++ }
        "WARN" { $warnCount++ }
        "FAIL" { $failCount++ }
    }
    
    # System resources
    $resourceResults = Test-SystemResources
    $checks += $resourceResults
    foreach ($result in $resourceResults) {
        switch ($result.Status) {
            "PASS" { $passCount++ }
            "WARN" { $warnCount++ }
            "FAIL" { $failCount++ }
        }
    }
    
    # Configuration
    $configResult = Test-ConfigurationHealth
    $checks += $configResult
    switch ($configResult.Status) {
        "PASS" { $passCount++ }
        "WARN" { $warnCount++ }
        "FAIL" { $failCount++ }
    }
    
    # Network
    $networkResults = Test-NetworkConnectivity
    $checks += $networkResults
    foreach ($result in $networkResults) {
        switch ($result.Status) {
            "PASS" { $passCount++ }
            "WARN" { $warnCount++ }
            "FAIL" { $failCount++ }
        }
    }
    
    # Performance (if service is running)
    if ($serviceResult.Status -eq "PASS") {
        $perfResults = Test-Performance
        $checks += $perfResults
        foreach ($result in $perfResults) {
            switch ($result.Status) {
                "PASS" { $passCount++ }
                "WARN" { $warnCount++ }
                "FAIL" { $failCount++ }
            }
        }
    }
    
    # Determine overall status
    if ($failCount -gt 0) {
        $report.OverallStatus = "CRITICAL"
    }
    elseif ($warnCount -gt 0) {
        $report.OverallStatus = "WARNING"
    }
    else {
        $report.OverallStatus = "HEALTHY"
    }
    
    $report.Checks = $checks
    $report.Summary = @{
        Total = $passCount + $warnCount + $failCount
        Passed = $passCount
        Warnings = $warnCount
        Failed = $failCount
    }
    
    # Output
    Write-Log ""
    Write-Log "Health Check Complete" $(if ($report.OverallStatus -eq "HEALTHY") { "SUCCESS" } elseif ($report.OverallStatus -eq "WARNING") { "WARNING" } else { "ERROR" })
    Write-Log "Status: $($report.OverallStatus)"
    Write-Log "Passed: $passCount, Warnings: $warnCount, Failed: $failCount"
    
    # Save report
    if ($OutputFile) {
        $report | ConvertTo-Json -Depth 5 | Out-File $OutputFile
        Write-Log "Report saved: $OutputFile"
    }
    
    return $report
}

# Main execution
Write-Log "RawrXD Health Check v1.0"
Write-Log "Mode: $Mode"
Write-Log ""

$report = Invoke-FullHealthCheck

# Exit code based on status
if ($report.OverallStatus -eq "CRITICAL") {
    exit 2
}
elseif ($report.OverallStatus -eq "WARNING") {
    exit 1
}
else {
    exit 0
}
