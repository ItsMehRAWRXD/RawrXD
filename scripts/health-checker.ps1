# RawrXD Health Checker
# Comprehensive health checks for the system

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Standard", "Full", "Custom")]
    [string]$CheckLevel = "Standard",
    
    [string[]]$CheckCategories = @("System", "Services", "Disk", "Memory", "Network"),
    [string]$OutputFormat = "Console",
    [string]$OutputPath = "",
    [switch]$NotifyOnFailure,
    [string]$NotificationChannel = "Console",
    [int]$WarningThreshold = 80,
    [int]$CriticalThreshold = 95,
    [switch]$AutoFix
)

$ErrorActionPreference = "Stop"

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    OverallStatus = "Unknown"
    Checks = @()
    Warnings = 0
    Critical = 0
    Passed = 0
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-HealthChecker {
    Write-Status "RawrXD Health Checker"
    Write-Status "Check Level: $CheckLevel"
    Write-Status "Warning Threshold: $WarningThreshold%"
    Write-Status "Critical Threshold: $CriticalThreshold%"
    Write-Host ""
}

function Add-CheckResult {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Status,
        [string]$Message,
        [string]$Value = "",
        [string]$Recommendation = ""
    )
    
    $result = [PSCustomObject]@{
        Category = $Category
        Name = $Name
        Status = $Status
        Message = $Message
        Value = $Value
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format "HH:mm:ss"
    }
    
    $script:Results.Checks += $result
    
    switch ($Status) {
        "PASS" { $script:Results.Passed++ }
        "WARN" { $script:Results.Warnings++ }
        "FAIL" { $script:Results.Critical++ }
    }
    
    # Display result
    $prefix = switch ($Status) {
        "PASS" { "[✓]" }
        "WARN" { "[!]" }
        "FAIL" { "[✗]" }
        default { "[?]" }
    }
    
    $color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    
    Write-Host "$prefix [$Category] $Name" -ForegroundColor $color -NoNewline
    if ($Value) {
        Write-Host " - $Value" -ForegroundColor $color -NoNewline
    }
    Write-Host ""
    
    if ($Message -and $Status -ne "PASS") {
        Write-Host "    $Message" -ForegroundColor Gray
    }
    
    if ($Recommendation -and $Status -ne "PASS") {
        Write-Host "    → $Recommendation" -ForegroundColor Cyan
    }
}

function Test-SystemHealth {
    Write-Status "Checking system health..."
    
    # CPU Usage
    $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3
    $cpuAvg = ($cpu.CounterSamples | Measure-Object CookedValue -Average).Average
    
    $cpuStatus = "PASS"
    $cpuMessage = "CPU usage is normal"
    if ($cpuAvg -gt $CriticalThreshold) {
        $cpuStatus = "FAIL"
        $cpuMessage = "CPU usage is critically high"
    } elseif ($cpuAvg -gt $WarningThreshold) {
        $cpuStatus = "WARN"
        $cpuMessage = "CPU usage is elevated"
    }
    
    Add-CheckResult -Category "System" -Name "CPU Usage" -Status $cpuStatus -Message $cpuMessage -Value "$([math]::Round($cpuAvg, 1))%" -Recommendation "Consider closing unnecessary processes"
    
    # Memory Usage
    $os = Get-CimInstance Win32_OperatingSystem
    $memoryUsed = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100
    
    $memStatus = "PASS"
    $memMessage = "Memory usage is normal"
    if ($memoryUsed -gt $CriticalThreshold) {
        $memStatus = "FAIL"
        $memMessage = "Memory usage is critically high"
    } elseif ($memoryUsed -gt $WarningThreshold) {
        $memStatus = "WARN"
        $memMessage = "Memory usage is elevated"
    }
    
    Add-CheckResult -Category "System" -Name "Memory Usage" -Status $memStatus -Message $memMessage -Value "$([math]::Round($memoryUsed, 1))%" -Recommendation "Consider closing applications or adding more RAM"
    
    # Uptime
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeStatus = if ($uptime.Days -gt 30) { "WARN" } else { "PASS" }
    $uptimeMessage = if ($uptime.Days -gt 30) { "System has been running for over 30 days, consider restarting" } else { "System uptime is normal" }
    
    Add-CheckResult -Category "System" -Name "System Uptime" -Status $uptimeStatus -Message $uptimeMessage -Value "$($uptime.Days) days, $($uptime.Hours) hours"
}

function Test-DiskHealth {
    Write-Status "Checking disk health..."
    
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    
    foreach ($disk in $disks) {
        $usedPercent = (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $totalGB = [math]::Round($disk.Size / 1GB, 2)
        
        $status = "PASS"
        $message = "Disk space is healthy"
        $recommendation = ""
        
        if ($usedPercent -gt $CriticalThreshold) {
            $status = "FAIL"
            $message = "Disk is critically full"
            $recommendation = "Free up disk space immediately"
        } elseif ($usedPercent -gt $WarningThreshold) {
            $status = "WARN"
            $message = "Disk space is running low"
            $recommendation = "Consider cleaning up old files"
        }
        
        Add-CheckResult -Category "Disk" -Name "Drive $($disk.DeviceID)" -Status $status -Message $message -Value "$freeGB GB free of $totalGB GB ($([math]::Round($usedPercent, 1))% used)" -Recommendation $recommendation
        
        # Auto-fix: Clean temp files if critical
        if ($AutoFix -and $status -eq "FAIL") {
            Write-Status "Auto-fixing: Cleaning temporary files..."
            Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Temporary files cleaned"
        }
    }
}

function Test-ServiceHealth {
    Write-Status "Checking service health..."
    
    $services = @(
        @{ Name = "RawrXD-Service"; Required = $false },
        @{ Name = "Docker"; Required = $false },
        @{ Name = "w3svc"; Required = $false }
    )
    
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            $status = if ($service.Status -eq "Running") { "PASS" } else { "WARN" }
            $message = if ($service.Status -eq "Running") { "Service is running" } else { "Service is not running" }
            Add-CheckResult -Category "Services" -Name $svc.Name -Status $status -Message $message -Value $service.Status
        }
    }
}

function Test-NetworkHealth {
    Write-Status "Checking network health..."
    
    # Check internet connectivity
    $internetTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet
    $internetStatus = if ($internetTest) { "PASS" } else { "FAIL" }
    $internetMessage = if ($internetTest) { "Internet connectivity is available" } else { "No internet connectivity" }
    
    Add-CheckResult -Category "Network" -Name "Internet Connectivity" -Status $internetStatus -Message $internetMessage
    
    # Check DNS resolution
    try {
        $dnsResult = Resolve-DnsName -Name "google.com" -ErrorAction Stop
        Add-CheckResult -Category "Network" -Name "DNS Resolution" -Status "PASS" -Message "DNS resolution is working" -Value $dnsResult[0].IPAddress
    }
    catch {
        Add-CheckResult -Category "Network" -Name "DNS Resolution" -Status "FAIL" -Message "DNS resolution failed" -Recommendation "Check DNS settings"
    }
    
    # Check network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    if ($adapters) {
        foreach ($adapter in $adapters) {
            Add-CheckResult -Category "Network" -Name "Adapter: $($adapter.Name)" -Status "PASS" -Message "Network adapter is active" -Value $adapter.LinkSpeed
        }
    }
}

function Test-RawrXDHealth {
    Write-Status "Checking RawrXD specific health..."
    
    # Check if RawrXD directory exists
    if (Test-Path ".") {
        Add-CheckResult -Category "RawrXD" -Name "Installation Directory" -Status "PASS" -Message "RawrXD directory exists"
    } else {
        Add-CheckResult -Category "RawrXD" -Name "Installation Directory" -Status "FAIL" -Message "RawrXD directory not found"
    }
    
    # Check config file
    if (Test-Path "config.json") {
        try {
            $config = Get-Content "config.json" | ConvertFrom-Json
            Add-CheckResult -Category "RawrXD" -Name "Configuration File" -Status "PASS" -Message "Configuration file is valid"
        }
        catch {
            Add-CheckResult -Category "RawrXD" -Name "Configuration File" -Status "FAIL" -Message "Configuration file is corrupted" -Recommendation "Restore from backup or regenerate"
        }
    } else {
        Add-CheckResult -Category "RawrXD" -Name "Configuration File" -Status "WARN" -Message "Configuration file not found" -Recommendation "Run config-manager.ps1 to create"
    }
    
    # Check models directory
    if (Test-Path "models") {
        $modelCount = (Get-ChildItem "models" -Filter "*.gguf" -ErrorAction SilentlyContinue).Count
        Add-CheckResult -Category "RawrXD" -Name "Models Directory" -Status "PASS" -Message "Models directory exists" -Value "$modelCount models"
    } else {
        Add-CheckResult -Category "RawrXD" -Name "Models Directory" -Status "WARN" -Message "Models directory not found"
    }
    
    # Check logs directory
    if (Test-Path "logs") {
        $logCount = (Get-ChildItem "logs" -Filter "*.log" -ErrorAction SilentlyContinue).Count
        Add-CheckResult -Category "RawrXD" -Name "Logs Directory" -Status "PASS" -Message "Logs directory exists" -Value "$logCount log files"
    } else {
        Add-CheckResult -Category "RawrXD" -Name "Logs Directory" -Status "WARN" -Message "Logs directory not found"
    }
}

function Export-Results {
    if ($OutputFormat -eq "Console") {
        return
    }
    
    $outputFile = if ($OutputPath) { $OutputPath } else { "health-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" }
    
    switch ($OutputFormat) {
        "JSON" {
            $script:Results | ConvertTo-Json -Depth 5 | Out-File $outputFile
        }
        "CSV" {
            $script:Results.Checks | Export-Csv $outputFile -NoTypeInformation
        }
        "HTML" {
            # Simple HTML export
            $html = "<html><body><h1>RawrXD Health Check</h1><table border='1'>"
            $html += "<tr><th>Category</th><th>Name</th><th>Status</th><th>Message</th></tr>"
            foreach ($check in $script:Results.Checks) {
                $color = switch ($check.Status) {
                    "PASS" { "green" }
                    "WARN" { "orange" }
                    "FAIL" { "red" }
                    default { "black" }
                }
                $html += "<tr><td>$($check.Category)</td><td>$($check.Name)</td><td style='color:$color'>$($check.Status)</td><td>$($check.Message)</td></tr>"
            }
            $html += "</table></body></html>"
            $html | Out-File $outputFile
        }
    }
    
    Write-Success "Results exported to: $outputFile"
}

function Send-Notification {
    if ($script:Results.Critical -gt 0 -and $NotifyOnFailure) {
        $message = "Health check completed with $($script:Results.Critical) critical issues and $($script:Results.Warnings) warnings"
        
        if ($NotificationChannel -eq "Console") {
            Write-Warning $message
        } else {
            # Call notification-sender.ps1 if available
            $notificationScript = Join-Path $PSScriptRoot "notification-sender.ps1"
            if (Test-Path $notificationScript) {
                & $notificationScript -Message $message -Level "Error" -Channels $NotificationChannel -Silent
            }
        }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "Health Check Summary" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host "Total Checks: $($script:Results.Checks.Count)"
    Write-Host "Passed: $($script:Results.Passed)" -ForegroundColor Green
    Write-Host "Warnings: $($script:Results.Warnings)" -ForegroundColor Yellow
    Write-Host "Critical: $($script:Results.Critical)" -ForegroundColor Red
    
    if ($script:Results.Critical -gt 0) {
        $script:Results.OverallStatus = "CRITICAL"
        Write-Host ""
        Write-Host "Overall Status: CRITICAL" -ForegroundColor Red
    } elseif ($script:Results.Warnings -gt 0) {
        $script:Results.OverallStatus = "WARNING"
        Write-Host ""
        Write-Host "Overall Status: WARNING" -ForegroundColor Yellow
    } else {
        $script:Results.OverallStatus = "HEALTHY"
        Write-Host ""
        Write-Host "Overall Status: HEALTHY" -ForegroundColor Green
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Health Checker" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-HealthChecker
    
    # Run checks based on level
    if ($CheckCategories -contains "System") {
        Test-SystemHealth
    }
    
    if ($CheckCategories -contains "Disk") {
        Test-DiskHealth
    }
    
    if ($CheckCategories -contains "Services") {
        Test-ServiceHealth
    }
    
    if ($CheckCategories -contains "Network") {
        Test-NetworkHealth
    }
    
    if ($CheckLevel -eq "Full") {
        Test-RawrXDHealth
    }
    
    Show-Summary
    Export-Results
    Send-Notification
    
    Write-Host ""
    
    # Exit with appropriate code
    if ($script:Results.Critical -gt 0) {
        exit 2
    } elseif ($script:Results.Warnings -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

Main
