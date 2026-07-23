# RawrXD Workspace Health Monitor
# Continuous monitoring of workspace health, disk space, and system resources

param(
    [switch]$Continuous,
    [int]$IntervalSeconds = 60,
    [string]$AlertThreshold = "80%",
    [string]$LogPath = "logs/health-monitor.log",
    [switch]$EmailAlerts,
    [string]$SmtpServer,
    [string]$AlertEmail,
    [switch]$ExportMetrics,
    [string]$MetricsEndpoint
)

$ErrorActionPreference = "Stop"

# Health thresholds
$HealthConfig = @{
    DiskThresholdPercent = 80
    MemoryThresholdPercent = 85
    CpuThresholdPercent = 90
    ProcessCountThreshold = 500
    TempFileAgeDays = 7
    LogFileAgeDays = 30
}

$script:HealthState = @{
    StartTime = Get-Date
    Alerts = @()
    Metrics = @{}
    LastCheck = $null
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Initialize-Monitor {
    # Create log directory
    $logDir = [System.IO.Path]::GetDirectoryName($LogPath)
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    Write-Success "Health monitor initialized"
}

function Get-DiskHealth {
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $results = @()
    
    foreach ($disk in $disks) {
        $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        $usedPercent = 100 - $freePercent
        
        $result = @{
            Drive = $disk.DeviceID
            TotalGB = [math]::Round($disk.Size / 1GB, 2)
            FreeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            UsedPercent = $usedPercent
            FreePercent = $freePercent
            Status = if ($usedPercent -gt $HealthConfig.DiskThresholdPercent) { "WARNING" } else { "OK" }
        }
        
        $results += $result
        
        if ($result.Status -eq "WARNING") {
            $script:HealthState.Alerts += @{
                Type = "DiskSpace"
                Severity = "High"
                Message = "Drive $($disk.DeviceID) is $usedPercent% full"
                Timestamp = Get-Date -Format "o"
            }
        }
    }
    
    return $results
}

function Get-MemoryHealth {
    $memory = Get-CimInstance Win32_OperatingSystem
    $totalGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
    $freeGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
    $usedGB = $totalGB - $freeGB
    $usedPercent = [math]::Round(($usedGB / $totalGB) * 100, 2)
    
    $result = @{
        TotalGB = $totalGB
        FreeGB = $freeGB
        UsedGB = $usedGB
        UsedPercent = $usedPercent
        Status = if ($usedPercent -gt $HealthConfig.MemoryThresholdPercent) { "WARNING" } else { "OK" }
    }
    
    if ($result.Status -eq "WARNING") {
        $script:HealthState.Alerts += @{
            Type = "Memory"
            Severity = "High"
            Message = "Memory usage is $usedPercent%"
            Timestamp = Get-Date -Format "o"
        }
    }
    
    return $result
}

function Get-CpuHealth {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $loadPercent = $cpu.LoadPercentage
    
    $result = @{
        Name = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        LoadPercent = $loadPercent
        Status = if ($loadPercent -gt $HealthConfig.CpuThresholdPercent) { "WARNING" } else { "OK" }
    }
    
    if ($result.Status -eq "WARNING") {
        $script:HealthState.Alerts += @{
            Type = "CPU"
            Severity = "Medium"
            Message = "CPU load is $loadPercent%"
            Timestamp = Get-Date -Format "o"
        }
    }
    
    return $result
}

function Get-ProcessHealth {
    $processes = Get-Process
    $processCount = $processes.Count
    
    # Find high CPU processes
    $highCpuProcesses = $processes | 
        Sort-Object CPU -Descending | 
        Select-Object -First 5 |
        ForEach-Object { 
            @{
                Name = $_.ProcessName
                Id = $_.Id
                Cpu = [math]::Round($_.CPU, 2)
                MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
            }
        }
    
    # Find high memory processes
    $highMemoryProcesses = $processes | 
        Sort-Object WorkingSet64 -Descending | 
        Select-Object -First 5 |
        ForEach-Object { 
            @{
                Name = $_.ProcessName
                Id = $_.Id
                MemoryMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
            }
        }
    
    $result = @{
        TotalProcesses = $processCount
        HighCpuProcesses = $highCpuProcesses
        HighMemoryProcesses = $highMemoryProcesses
        Status = if ($processCount -gt $HealthConfig.ProcessCountThreshold) { "WARNING" } else { "OK" }
    }
    
    return $result
}

function Get-BuildHealth {
    # Check build directory size
    $buildDir = "D:\rawrxd\build"
    $buildSize = 0
    
    if (Test-Path $buildDir) {
        $buildSize = (Get-ChildItem $buildDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
    }
    
    # Check for build artifacts older than 7 days
    $oldArtifacts = @()
    if (Test-Path $buildDir) {
        $oldArtifacts = Get-ChildItem $buildDir -Recurse -File | 
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
    }
    
    $result = @{
        BuildDirSizeGB = [math]::Round($buildSize / 1GB, 2)
        OldArtifactsCount = $oldArtifacts.Count
        Status = if ($buildSize -gt 50GB) { "WARNING" } else { "OK" }
    }
    
    if ($result.Status -eq "WARNING") {
        $script:HealthState.Alerts += @{
            Type = "BuildDirectory"
            Severity = "Low"
            Message = "Build directory is $($result.BuildDirSizeGB)GB"
            Timestamp = Get-Date -Format "o"
        }
    }
    
    return $result
}

function Get-CleanupHealth {
    # Check temp files
    $tempDirs = @($env:TEMP, "C:\Windows\Temp")
    $tempFileCount = 0
    $oldTempFiles = 0
    
    foreach ($tempDir in $tempDirs) {
        if (Test-Path $tempDir) {
            $files = Get-ChildItem $tempDir -File -ErrorAction SilentlyContinue
            $tempFileCount += $files.Count
            $oldTempFiles += ($files | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$HealthConfig.TempFileAgeDays) }).Count
        }
    }
    
    # Check log files
    $logDirs = @("logs", "D:\rawrxd\logs")
    $oldLogFiles = 0
    
    foreach ($logDir in $logDirs) {
        if (Test-Path $logDir) {
            $oldLogFiles += (Get-ChildItem $logDir -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$HealthConfig.LogFileAgeDays) }).Count
        }
    }
    
    $result = @{
        TempFileCount = $tempFileCount
        OldTempFiles = $oldTempFiles
        OldLogFiles = $oldLogFiles
        Status = if ($oldTempFiles -gt 1000 -or $oldLogFiles -gt 100) { "WARNING" } else { "OK" }
    }
    
    return $result
}

function Invoke-HealthCheck {
    $script:HealthState.LastCheck = Get-Date
    $script:HealthState.Alerts = @()
    
    $health = @{
        Timestamp = Get-Date -Format "o"
        Disk = Get-DiskHealth
        Memory = Get-MemoryHealth
        CPU = Get-CpuHealth
        Processes = Get-ProcessHealth
        Build = Get-BuildHealth
        Cleanup = Get-CleanupHealth
    }
    
    $script:HealthState.Metrics = $health
    
    return $health
}

function Show-HealthStatus {
    param([hashtable]$Health)
    
    Clear-Host
    Write-Host "RawrXD Workspace Health Monitor" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "Last Check: $($Health.Timestamp)" -ForegroundColor Gray
    Write-Host ""
    
    # Disk Status
    Write-Host "Disk Space:" -ForegroundColor White
    foreach ($disk in $Health.Disk) {
        $color = if ($disk.Status -eq "OK") { 'Green' } else { 'Red' }
        Write-Host "  $($disk.Drive) $($disk.UsedPercent)% used ($($disk.FreeGB)GB free)" -ForegroundColor $color
    }
    
    Write-Host ""
    
    # Memory Status
    Write-Host "Memory:" -ForegroundColor White
    $memColor = if ($Health.Memory.Status -eq "OK") { 'Green' } else { 'Red' }
    Write-Host "  $($Health.Memory.UsedPercent)% used ($($Health.Memory.FreeGB)GB free / $($Health.Memory.TotalGB)GB total)" -ForegroundColor $memColor
    
    Write-Host ""
    
    # CPU Status
    Write-Host "CPU:" -ForegroundColor White
    $cpuColor = if ($Health.CPU.Status -eq "OK") { 'Green' } else { 'Red' }
    Write-Host "  $($Health.CPU.LoadPercent)% load ($($Health.CPU.LogicalProcessors) logical processors)" -ForegroundColor $cpuColor
    
    Write-Host ""
    
    # Process Status
    Write-Host "Top Processes by CPU:" -ForegroundColor White
    foreach ($proc in $Health.Processes.HighCpuProcesses | Select-Object -First 3) {
        Write-Host "  $($proc.Name) (PID: $($proc.Id)): $($proc.Cpu) CPU, $($proc.MemoryMB)MB RAM" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Build Status
    Write-Host "Build Directory:" -ForegroundColor White
    $buildColor = if ($Health.Build.Status -eq "OK") { 'Green' } else { 'Yellow' }
    Write-Host "  Size: $($Health.Build.BuildDirSizeGB)GB, Old artifacts: $($Health.Build.OldArtifactsCount)" -ForegroundColor $buildColor
    
    Write-Host ""
    
    # Cleanup Status
    Write-Host "Cleanup:" -ForegroundColor White
    Write-Host "  Temp files: $($Health.Cleanup.TempFileCount), Old temp: $($Health.Cleanup.OldTempFiles), Old logs: $($Health.Cleanup.OldLogFiles)" -ForegroundColor Gray
    
    Write-Host ""
    
    # Alerts
    if ($script:HealthState.Alerts.Count -gt 0) {
        Write-Host "⚠️  Alerts ($($script:HealthState.Alerts.Count)):" -ForegroundColor Yellow
        foreach ($alert in $script:HealthState.Alerts | Select-Object -First 5) {
            $color = switch ($alert.Severity) {
                "High" { 'Red' }
                "Medium" { 'Yellow' }
                default { 'DarkYellow' }
            }
            Write-Host "  [$($alert.Severity)] $($alert.Message)" -ForegroundColor $color
        }
    } else {
        Write-Host "✅ All systems healthy" -ForegroundColor Green
    }
}

function Send-AlertEmail {
    if (-not $EmailAlerts -or -not $SmtpServer -or -not $AlertEmail) {
        return
    }
    
    if ($script:HealthState.Alerts.Count -eq 0) {
        return
    }
    
    $subject = "RawrXD Health Alert - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $body = "The following alerts were detected:`n`n"
    
    foreach ($alert in $script:HealthState.Alerts) {
        $body += "[$($alert.Severity)] $($alert.Message)`n"
    }
    
    try {
        # Would use Send-MailMessage or similar
        Write-Verbose "Alert email would be sent to $AlertEmail"
    } catch {
        Write-Warning "Failed to send alert email: $_"
    }
}

function Export-Metrics {
    if (-not $ExportMetrics) { return }
    
    $metrics = @{
        Timestamp = Get-Date -Format "o"
        DiskUsedPercent = ($script:HealthState.Metrics.Disk | Measure-Object -Property UsedPercent -Average).Average
        MemoryUsedPercent = $script:HealthState.Metrics.Memory.UsedPercent
        CpuLoadPercent = $script:HealthState.Metrics.CPU.LoadPercent
        ProcessCount = $script:HealthState.Metrics.Processes.TotalProcesses
        AlertCount = $script:HealthState.Alerts.Count
    }
    
    if ($MetricsEndpoint) {
        try {
            $json = $metrics | ConvertTo-Json
            Invoke-RestMethod -Uri $MetricsEndpoint -Method POST -Body $json -ContentType "application/json"
        } catch {
            Write-Verbose "Failed to export metrics: $_"
        }
    }
    
    # Also log locally
    $metrics | ConvertTo-Json | Out-File $LogPath -Append
}

function Invoke-Cleanup {
    Write-Status "Running cleanup tasks..."
    
    # Clean old temp files
    $tempDirs = @($env:TEMP, "C:\Windows\Temp")
    $cleaned = 0
    
    foreach ($tempDir in $tempDirs) {
        if (Test-Path $tempDir) {
            $oldFiles = Get-ChildItem $tempDir -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$HealthConfig.TempFileAgeDays) }
            
            foreach ($file in $oldFiles) {
                try {
                    Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                    $cleaned++
                } catch {}
            }
        }
    }
    
    # Clean old log files
    $logDirs = @("logs", "D:\rawrxd\logs")
    
    foreach ($logDir in $logDirs) {
        if (Test-Path $logDir) {
            $oldLogs = Get-ChildItem $logDir -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$HealthConfig.LogFileAgeDays) }
            
            foreach ($log in $oldLogs) {
                try {
                    Remove-Item $log.FullName -Force -ErrorAction SilentlyContinue
                    $cleaned++
                } catch {}
            }
        }
    }
    
    if ($cleaned -gt 0) {
        Write-Success "Cleaned up $cleaned old files"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Workspace Health Monitor" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Monitor
    
    if ($Continuous) {
        Write-Status "Starting continuous monitoring (interval: ${IntervalSeconds}s)"
        Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
        Write-Host ""
        
        while ($true) {
            $health = Invoke-HealthCheck
            Show-HealthStatus -Health $health
            Send-AlertEmail
            Export-Metrics
            
            # Auto-cleanup if too many old files
            if ($health.Cleanup.OldTempFiles -gt 1000 -or $health.Cleanup.OldLogFiles -gt 100) {
                Invoke-Cleanup
            }
            
            Start-Sleep -Seconds $IntervalSeconds
        }
    } else {
        Write-Status "Running single health check..."
        $health = Invoke-HealthCheck
        Show-HealthStatus -Health $health
        Send-AlertEmail
        Export-Metrics
        
        if ($script:HealthState.Alerts.Count -gt 0) {
            Write-Host ""
            $response = Read-Host "Run cleanup tasks? (y/N)"
            if ($response -eq "y") {
                Invoke-Cleanup
            }
        }
    }
    
    Write-Host ""
    Write-Success "Health monitoring complete"
}

Main
