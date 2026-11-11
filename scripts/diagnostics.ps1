# RawrXD System Diagnostics
# Comprehensive system health and diagnostics checker

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quick", "Full", "Performance", "Network", "Hardware")]
    [string]$ScanType = "Quick",
    
    [string]$OutputPath = "diagnostics",
    [switch]$FixIssues,
    [switch]$ExportReport,
    [string]$EmailReport
)

$ErrorActionPreference = "Stop"

# Diagnostic checks configuration
$DiagnosticChecks = @{
    Quick = @(
        "SystemInfo",
        "DiskSpace",
        "Memory",
        "Services",
        "LogErrors"
    )
    Full = @(
        "SystemInfo",
        "DiskSpace",
        "Memory",
        "CPU",
        "Services",
        "Network",
        "Firewall",
        "LogErrors",
        "Configuration",
        "Dependencies",
        "PerformanceCounters"
    )
    Performance = @(
        "CPU",
        "Memory",
        "DiskPerformance",
        "GPU",
        "PerformanceCounters"
    )
    Network = @(
        "Network",
        "Firewall",
        "Ports",
        "Connectivity"
    )
    Hardware = @(
        "SystemInfo",
        "CPU",
        "Memory",
        "DiskHealth",
        "GPU",
        "Temperature"
    )
}

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    ScanType = $ScanType
    Checks = @{}
    Issues = @()
    Recommendations = @()
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

function Initialize-Diagnostics {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Status "Starting $ScanType diagnostics scan..."
    Write-Status "Output directory: $OutputPath"
}

# Individual diagnostic checks
function Test-SystemInfo {
    Write-Status "Gathering system information..."
    
    $info = @{
        ComputerName = $env:COMPUTERNAME
        OS = (Get-WmiObject Win32_OperatingSystem).Caption
        Version = (Get-WmiObject Win32_OperatingSystem).Version
        Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        Uptime = (Get-Date) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    $script:Results.Checks.SystemInfo = $info
    Write-Success "System info collected"
}

function Test-DiskSpace {
    Write-Status "Checking disk space..."
    
    $disks = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $diskInfo = @()
    
    foreach ($disk in $disks) {
        $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        $sizeGB = [math]::Round($disk.Size / 1GB, 2)
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        
        $status = "OK"
        if ($freePercent -lt 5) {
            $status = "CRITICAL"
            $script:Issues += "Disk $($disk.DeviceID) critically low on space ($freePercent% free)"
        } elseif ($freePercent -lt 15) {
            $status = "WARNING"
            $script:Recommendations += "Consider freeing space on $($disk.DeviceID) ($freePercent% free)"
        }
        
        $diskInfo += @{
            Drive = $disk.DeviceID
            SizeGB = $sizeGB
            FreeGB = $freeGB
            FreePercent = $freePercent
            Status = $status
        }
    }
    
    $script:Results.Checks.DiskSpace = $diskInfo
    Write-Success "Disk space checked"
}

function Test-Memory {
    Write-Status "Checking memory..."
    
    $os = Get-WmiObject Win32_OperatingSystem
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedPercent = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 2)
    
    $status = "OK"
    if ($usedPercent -gt 90) {
        $status = "CRITICAL"
        $script:Issues += "Memory usage critically high ($usedPercent%)"
    } elseif ($usedPercent -gt 80) {
        $status = "WARNING"
        $script:Recommendations += "High memory usage detected ($usedPercent%)"
    }
    
    $script:Results.Checks.Memory = @{
        TotalGB = $totalGB
        FreeGB = $freeGB
        UsedPercent = $usedPercent
        Status = $status
    }
    
    Write-Success "Memory checked"
}

function Test-CPU {
    Write-Status "Checking CPU..."
    
    $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
    $load = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
    
    $status = "OK"
    if ($load -gt 90) {
        $status = "HIGH"
        $script:Recommendations += "High CPU load detected ($load%)"
    }
    
    $script:Results.Checks.CPU = @{
        Name = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        LoadPercent = $load
        Status = $status
    }
    
    Write-Success "CPU checked"
}

function Test-Services {
    Write-Status "Checking RawrXD services..."
    
    $services = @("RawrXD", "RawrXD-API", "RawrXD-Worker")
    $serviceStatus = @()
    
    foreach ($serviceName in $services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            $serviceStatus += @{
                Name = $serviceName
                Status = $service.Status
                StartType = $service.StartType
            }
            
            if ($service.Status -ne "Running") {
                $script:Issues += "Service $serviceName is not running"
                
                if ($FixIssues) {
                    Write-Status "Attempting to start $serviceName..."
                    try {
                        Start-Service $serviceName
                        Write-Success "Started $serviceName"
                    }
                    catch {
                        Write-Error "Failed to start $serviceName`: $_"
                    }
                }
            }
        }
    }
    
    $script:Results.Checks.Services = $serviceStatus
    Write-Success "Services checked"
}

function Test-Network {
    Write-Status "Checking network configuration..."
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $networkInfo = @()
    
    foreach ($adapter in $adapters) {
        $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $networkInfo += @{
            Name = $adapter.Name
            MacAddress = $adapter.MacAddress
            IPAddress = if ($ip) { $ip.IPAddress } else { "N/A" }
            Speed = $adapter.LinkSpeed
        }
    }
    
    $script:Results.Checks.Network = $networkInfo
    Write-Success "Network checked"
}

function Test-LogErrors {
    Write-Status "Checking for recent errors..."
    
    $errors = @()
    
    # Check Windows Event Log
    $eventLogErrors = Get-EventLog -LogName Application -EntryType Error -After (Get-Date).AddHours(-24) -ErrorAction SilentlyContinue | 
        Where-Object { $_.Source -like "*RawrXD*" } |
        Select-Object -First 10
    
    foreach ($error in $eventLogErrors) {
        $errors += @{
            Time = $error.TimeGenerated
            Source = $error.Source
            Message = $error.Message.Substring(0, [Math]::Min(200, $error.Message.Length))
        }
    }
    
    # Check log files
    if (Test-Path "logs") {
        $logFiles = Get-ChildItem "logs\*.log" -ErrorAction SilentlyContinue | Select-Object -Last 5
        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -Tail 100
            $errorLines = $content | Select-String "ERROR|FATAL|Exception" | Select-Object -First 5
            foreach ($line in $errorLines) {
                $errors += @{
                    Time = $logFile.LastWriteTime
                    Source = $logFile.Name
                    Message = $line.Line.Substring(0, [Math]::Min(200, $line.Line.Length))
                }
            }
        }
    }
    
    $script:Results.Checks.LogErrors = $errors
    
    if ($errors.Count -gt 0) {
        $script:Recommendations += "Found $($errors.Count) recent errors. Review logs for details."
    }
    
    Write-Success "Log errors checked"
}

function Test-Configuration {
    Write-Status "Checking configuration..."
    
    $configStatus = @()
    
    # Check config files
    $configFiles = @(
        "config.json",
        "appsettings.json",
        "rawrxd.config.json"
    )
    
    foreach ($configFile in $configFiles) {
        if (Test-Path $configFile) {
            try {
                $content = Get-Content $configFile -Raw
                $json = $content | ConvertFrom-Json -ErrorAction Stop
                $configStatus += @{
                    File = $configFile
                    Status = "Valid"
                    Size = (Get-Item $configFile).Length
                }
            }
            catch {
                $configStatus += @{
                    File = $configFile
                    Status = "Invalid JSON"
                    Error = $_.Exception.Message
                }
                $script:Issues += "Configuration file $configFile has invalid JSON"
            }
        }
    }
    
    $script:Results.Checks.Configuration = $configStatus
    Write-Success "Configuration checked"
}

function Test-Dependencies {
    Write-Status "Checking dependencies..."
    
    $dependencies = @{
        Required = @(
            @{ Name = "cmake"; Command = "cmake --version" },
            @{ Name = "git"; Command = "git --version" },
            @{ Name = "python"; Command = "python --version" }
        )
        Optional = @(
            @{ Name = "nvcc"; Command = "nvcc --version" },
            @{ Name = "docker"; Command = "docker --version" }
        )
    }
    
    $depStatus = @{
        Required = @()
        Optional = @()
        Missing = @()
    }
    
    foreach ($dep in $dependencies.Required) {
        $cmd = Get-Command $dep.Name -ErrorAction SilentlyContinue
        if ($cmd) {
            $version = Invoke-Expression $dep.Command 2>&1 | Select-Object -First 1
            $depStatus.Required += @{
                Name = $dep.Name
                Installed = $true
                Version = $version
            }
        } else {
            $depStatus.Required += @{
                Name = $dep.Name
                Installed = $false
            }
            $depStatus.Missing += $dep.Name
            $script:Issues += "Required dependency missing: $($dep.Name)"
        }
    }
    
    foreach ($dep in $dependencies.Optional) {
        $cmd = Get-Command $dep.Name -ErrorAction SilentlyContinue
        if ($cmd) {
            $version = Invoke-Expression $dep.Command 2>&1 | Select-Object -First 1
            $depStatus.Optional += @{
                Name = $dep.Name
                Installed = $true
                Version = $version
            }
        } else {
            $depStatus.Optional += @{
                Name = $dep.Name
                Installed = $false
            }
        }
    }
    
    $script:Results.Checks.Dependencies = $depStatus
    Write-Success "Dependencies checked"
}

function Show-Results {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Diagnostics Results" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # System summary
    if ($script:Results.Checks.SystemInfo) {
        Write-Host "System: $($script:Results.Checks.SystemInfo.ComputerName)" -ForegroundColor White
        Write-Host "OS: $($script:Results.Checks.SystemInfo.OS)" -ForegroundColor White
        Write-Host "Uptime: $($script:Results.Checks.SystemInfo.Uptime.ToString('dd\.hh\:mm\:ss'))" -ForegroundColor White
        Write-Host ""
    }
    
    # Issues
    if ($script:Results.Issues.Count -gt 0) {
        Write-Host "Issues Found: $($script:Results.Issues.Count)" -ForegroundColor Red
        foreach ($issue in $script:Results.Issues) {
            Write-Host "  ✗ $issue" -ForegroundColor Red
        }
        Write-Host ""
    } else {
        Write-Success "No critical issues found"
        Write-Host ""
    }
    
    # Recommendations
    if ($script:Results.Recommendations.Count -gt 0) {
        Write-Host "Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $script:Results.Recommendations) {
            Write-Host "  ! $rec" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    # Component status
    Write-Host "Component Status:" -ForegroundColor White
    foreach ($check in $script:Results.Checks.Keys) {
        $status = "✓"
        $color = "Green"
        
        if ($check -eq "DiskSpace") {
            $critical = $script:Results.Checks.DiskSpace | Where-Object { $_.Status -eq "CRITICAL" }
            if ($critical) {
                $status = "✗"
                $color = "Red"
            }
        }
        
        Write-Host "  $status $check" -ForegroundColor $color
    }
}

function Export-DiagnosticsReport {
    if (-not $ExportReport) {
        return
    }
    
    $reportFile = "$OutputPath\diagnostics-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Success "Report exported to: $reportFile"
    
    # Generate summary text file
    $summaryFile = "$OutputPath\diagnostics-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $summary = @"
RawrXD System Diagnostics Report
================================
Generated: $($script:Results.Timestamp)
Scan Type: $($script:Results.ScanType)

Issues Found: $($script:Results.Issues.Count)
Recommendations: $($script:Results.Recommendations.Count)

Issues:
$($script:Results.Issues | ForEach-Object { "- $_" } | Out-String)

Recommendations:
$($script:Results.Recommendations | ForEach-Object { "- $_" } | Out-String)

System Information:
$($script:Results.Checks.SystemInfo | ConvertTo-Json)
"@
    
    $summary | Out-File $summaryFile
    Write-Success "Summary saved to: $summaryFile"
}

# Main execution
function Main {
    Write-Host "RawrXD System Diagnostics" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Diagnostics
    
    $checksToRun = $DiagnosticChecks[$ScanType]
    
    foreach ($check in $checksToRun) {
        $functionName = "Test-$check"
        if (Get-Command $functionName -ErrorAction SilentlyContinue) {
            & $functionName
        }
    }
    
    Show-Results
    Export-DiagnosticsReport
    
    # Exit code based on issues
    if ($script:Results.Issues.Count -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

Main
