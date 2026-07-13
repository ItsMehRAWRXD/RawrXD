# RawrXD Health Check Automation
# Phase J Batch 2/5: Automated Health Checks
# Performs comprehensive health checks on the system

param(
    [Parameter()]
    [ValidateSet("Quick", "Full", "Deep", "Continuous")]
    [string]$CheckType = "Quick",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\operations",
    
    [Parameter()]
    [string]$ReportPath = "$PSScriptRoot\..\..\logs\operations\health_reports",
    
    [Parameter()]
    [switch]$AutoFix,
    
    [Parameter()]
    [switch]$Notify
)

# Health check configuration
$HealthConfig = @{
    Quick = @{
        Duration = 30
        Tests = @("Services", "DiskSpace", "Memory")
    }
    Full = @{
        Duration = 120
        Tests = @("Services", "DiskSpace", "Memory", "CPU", "Network", "Dependencies")
    }
    Deep = @{
        Duration = 300
        Tests = @("Services", "DiskSpace", "Memory", "CPU", "Network", "Dependencies", "Performance", "Security")
    }
}

# Ensure directories exist
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
if (-not (Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
}

function Write-HealthLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "health_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "PASS"  { "Green" }
        "HEALTH" { "Cyan" }
        "FIX"   { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Test-ServiceHealth {
    $results = @{
        Test = "Services"
        Passed = $true
        Details = @()
        Issues = @()
    }
    
    $services = @("RawrXD_Runtime", "RawrXD_Telemetry", "RawrXD_Monitor")
    
    foreach ($service in $services) {
        try {
            $svc = Get-Service $service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -eq "Running") {
                    $results.Details += @{ Service = $service; Status = "Running"; Healthy = $true }
                }
                else {
                    $results.Details += @{ Service = $service; Status = $svc.Status.ToString(); Healthy = $false }
                    $results.Issues += "Service $service is not running"
                    $results.Passed = $false
                }
            }
            else {
                $results.Details += @{ Service = $service; Status = "NotInstalled"; Healthy = $false }
            }
        }
        catch {
            $results.Details += @{ Service = $service; Status = "Error"; Healthy = $false }
            $results.Issues += "Failed to check service $service"
            $results.Passed = $false
        }
    }
    
    return $results
}

function Test-DiskSpace {
    $results = @{
        Test = "DiskSpace"
        Passed = $true
        Details = @()
        Issues = @()
    }
    
    $drives = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    
    foreach ($drive in $drives) {
        $freePercent = ($drive.FreeSpace / $drive.Size) * 100
        $driveLetter = $drive.DeviceID
        
        $results.Details += @{
            Drive = $driveLetter
            FreePercent = [math]::Round($freePercent, 2)
            FreeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            TotalGB = [math]::Round($drive.Size / 1GB, 2)
        }
        
        if ($freePercent -lt 5) {
            $results.Issues += "Drive $driveLetter critically low on space ($([math]::Round($freePercent, 1))% free)"
            $results.Passed = $false
        }
        elseif ($freePercent -lt 10) {
            $results.Issues += "Drive $driveLetter low on space ($([math]::Round($freePercent, 1))% free)"
        }
    }
    
    return $results
}

function Test-MemoryHealth {
    $results = @{
        Test = "Memory"
        Passed = $true
        Details = @{}
        Issues = @()
    }
    
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedPercent = (($totalGB - $freeGB) / $totalGB) * 100
        
        $results.Details = @{
            TotalGB = $totalGB
            FreeGB = $freeGB
            UsedPercent = [math]::Round($usedPercent, 2)
        }
        
        if ($usedPercent -gt 95) {
            $results.Issues += "Memory critically high: $([math]::Round($usedPercent, 1))% used"
            $results.Passed = $false
        }
        elseif ($usedPercent -gt 85) {
            $results.Issues += "Memory usage high: $([math]::Round($usedPercent, 1))% used"
        }
    }
    catch {
        $results.Issues += "Failed to check memory: $_"
        $results.Passed = $false
    }
    
    return $results
}

function Test-CPUHealth {
    $results = @{
        Test = "CPU"
        Passed = $true
        Details = @{}
        Issues = @()
    }
    
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3
        $avgCpu = ($cpu.CounterSamples | Measure-Object -Property CookedValue -Average).Average
        
        $results.Details = @{
            AverageUsage = [math]::Round($avgCpu, 2)
        }
        
        if ($avgCpu -gt 90) {
            $results.Issues += "CPU usage critically high: $([math]::Round($avgCpu, 1))%"
            $results.Passed = $false
        }
        elseif ($avgCpu -gt 75) {
            $results.Issues += "CPU usage high: $([math]::Round($avgCpu, 1))%"
        }
    }
    catch {
        $results.Issues += "Failed to check CPU: $_"
        $results.Passed = $false
    }
    
    return $results
}

function Test-NetworkHealth {
    $results = @{
        Test = "Network"
        Passed = $true
        Details = @{}
        Issues = @()
    }
    
    # Check network connectivity
    $testConnection = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
    
    $results.Details = @{
        InternetConnectivity = $testConnection
    }
    
    if (-not $testConnection) {
        $results.Issues += "No internet connectivity"
        $results.Passed = $false
    }
    
    return $results
}

function Test-Dependencies {
    $results = @{
        Test = "Dependencies"
        Passed = $true
        Details = @()
        Issues = @()
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    $results.Details += @{
        Component = "PowerShell"
        Version = "$($psVersion.Major).$($psVersion.Minor)"
        Required = "7.0"
        OK = $psVersion.Major -ge 7
    }
    
    if ($psVersion.Major -lt 7) {
        $results.Issues += "PowerShell version $psVersion is below required 7.0"
        $results.Passed = $false
    }
    
    return $results
}

function Invoke-AutoFix {
    param([array]$Issues)
    
    Write-HealthLog "Attempting automatic fixes..." "FIX"
    
    $fixed = @()
    $failed = @()
    
    foreach ($issue in $Issues) {
        if ($issue -match "Service (\w+) is not running") {
            $serviceName = $matches[1]
            try {
                Start-Service $serviceName -ErrorAction Stop
                $fixed += "Started service $serviceName"
                Write-HealthLog "Auto-fixed: Started service $serviceName" "FIX"
            }
            catch {
                $failed += "Failed to start service $serviceName"
                Write-HealthLog "Auto-fix failed for service $serviceName" "ERROR"
            }
        }
    }
    
    return @{
        Fixed = $fixed
        Failed = $failed
    }
}

function Invoke-HealthCheck {
    param([string]$Type)
    
    Write-HealthLog "Starting $Type health check..." "HEALTH"
    
    $config = $HealthConfig[$Type]
    $startTime = Get-Date
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Type = $Type
        Duration = 0
        Overall = "Unknown"
        Results = @{}
        Issues = @()
        AutoFixes = @()
    }
    
    # Run tests
    foreach ($test in $config.Tests) {
        $testFunction = "Test-${test}Health"
        if (Get-Command $testFunction -ErrorAction SilentlyContinue) {
            $result = & $testFunction
            $report.Results[$test] = $result
            
            if (-not $result.Passed) {
                $report.Issues += $result.Issues
            }
            
            $status = if ($result.Passed) { "PASS" } else { "FAIL" }
            Write-HealthLog "$test check: $status" $status
        }
    }
    
    # Auto-fix if enabled
    if ($AutoFix -and $report.Issues.Count -gt 0) {
        $fixResults = Invoke-AutoFix -Issues $report.Issues
        $report.AutoFixes = $fixResults
    }
    
    # Calculate overall status
    $passedTests = ($report.Results.Values | Where-Object { $_.Passed }).Count
    $totalTests = $report.Results.Count
    
    if ($passedTests -eq $totalTests) {
        $report.Overall = "Healthy"
    }
    elseif ($passedTests -ge ($totalTests * 0.7)) {
        $report.Overall = "Degraded"
    }
    else {
        $report.Overall = "Critical"
    }
    
    $report.Duration = ((Get-Date) - $startTime).TotalSeconds
    
    # Save report
    $reportFile = Join-Path $ReportPath "health_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile -Encoding UTF8
    
    Write-HealthLog "Health check complete. Overall: $($report.Overall), Duration: $([math]::Round($report.Duration, 2))s" "HEALTH"
    
    return $report
}

function Show-HealthStatus {
    $reports = Get-ChildItem -Path $ReportPath -Filter "health_report_*.json" | 
               Sort-Object LastWriteTime -Descending | 
               Select-Object -First 5
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Health Check Status                            ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($reports.Count -gt 0) {
        Write-Host "║ Recent Health Reports:" -ForegroundColor Cyan
        foreach ($report in $reports) {
            $data = Get-Content $report.FullName | ConvertFrom-Json
            $color = switch ($data.Overall) {
                "Healthy" { "Green" }
                "Degraded" { "Yellow" }
                "Critical" { "Red" }
                default { "Gray" }
            }
            Write-Host "║   [$($data.Overall)] $($data.Timestamp) ($($data.Type))" -ForegroundColor $color
        }
    }
    else {
        Write-Host "║ No health reports found" -ForegroundColor Yellow
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($CheckType) {
    "Quick" {
        $report = Invoke-HealthCheck -Type "Quick"
        $report | ConvertTo-Json -Depth 10
    }
    "Full" {
        $report = Invoke-HealthCheck -Type "Full"
        $report | ConvertTo-Json -Depth 10
    }
    "Deep" {
        $report = Invoke-HealthCheck -Type "Deep"
        $report | ConvertTo-Json -Depth 10
    }
    "Continuous" {
        Write-HealthLog "Starting continuous health monitoring..." "HEALTH"
        while ($true) {
            Invoke-HealthCheck -Type "Quick" | Out-Null
            Start-Sleep -Seconds 300  # Every 5 minutes
        }
    }
}

if ($CheckType -eq "ShowStatus") {
    Show-HealthStatus
}
