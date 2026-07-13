# daily_maintenance.ps1
# Phase K Batch 3/5: Automated Daily Maintenance Tasks

param(
    [string]$LogPath = "${env:ProgramData}\RawrXD\logs",
    [string]$BackupPath = "${env:ProgramData}\RawrXD\backups",
    [int]$LogRetentionDays = 7,
    [int]$BackupRetentionDays = 30,
    [switch]$CreateBackup
)

$ErrorActionPreference = "Continue"

$MaintenanceLog = @{
    Date = Get-Date -Format "yyyy-MM-dd"
    StartTime = Get-Date -Format "o"
    Tasks = @()
    Success = $true
}

function Write-MaintLog($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "TASK" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Invoke-MaintenanceTask($Name, $ScriptBlock) {
    Write-MaintLog "Task: $Name" "TASK"
    
    $startTime = Get-Date
    try {
        $result = & $ScriptBlock
        $duration = (Get-Date) - $startTime
        
        Write-MaintLog "✅ $Name completed in $([math]::Round($duration.TotalSeconds, 2))s" "SUCCESS"
        
        $MaintenanceLog.Tasks += @{
            Name = $Name
            Status = "SUCCESS"
            Duration = $duration.TotalSeconds
            Result = $result
        }
        
        return $true
    }
    catch {
        $duration = (Get-Date) - $startTime
        Write-MaintLog "❌ $Name failed: $_" "ERROR"
        
        $MaintenanceLog.Tasks += @{
            Name = $Name
            Status = "FAILED"
            Duration = $duration.TotalSeconds
            Error = $_.Exception.Message
        }
        
        $MaintenanceLog.Success = $false
        return $false
    }
}

# Task 1: Log Rotation
Invoke-MaintenanceTask "Log Rotation" {
    if (-not (Test-Path $LogPath)) {
        return "Log path does not exist"
    }
    
    $cutoffDate = (Get-Date).AddDays(-$LogRetentionDays)
    $oldLogs = Get-ChildItem -Path $LogPath -Filter "*.log" | Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    $deletedCount = 0
    foreach ($log in $oldLogs) {
        Remove-Item $log.FullName -Force
        $deletedCount++
    }
    
    return "Deleted $deletedCount old log files"
}

# Task 2: Backup Cleanup
Invoke-MaintenanceTask "Backup Cleanup" {
    if (-not (Test-Path $BackupPath)) {
        return "Backup path does not exist"
    }
    
    $cutoffDate = (Get-Date).AddDays(-$BackupRetentionDays)
    $oldBackups = Get-ChildItem -Path $BackupPath -Directory | Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    $deletedCount = 0
    foreach ($backup in $oldBackups) {
        Remove-Item $backup.FullName -Recurse -Force
        $deletedCount++
    }
    
    return "Deleted $deletedCount old backups"
}

# Task 3: Health Check
Invoke-MaintenanceTask "Health Check" {
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/health" -TimeoutSec 10
        
        if ($health.status -eq "healthy") {
            return "System healthy"
        } else {
            throw "System status: $($health.status)"
        }
    }
    catch {
        throw "Health check failed: $_"
    }
}

# Task 4: Metrics Collection
Invoke-MaintenanceTask "Metrics Collection" {
    try {
        $metrics = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/metrics" -TimeoutSec 10
        
        # Save daily metrics
        $dailyMetricsPath = "$LogPath\daily_metrics_$(Get-Date -Format 'yyyyMMdd').json"
        $metrics | ConvertTo-Json | Out-File $dailyMetricsPath
        
        return "Metrics saved to $dailyMetricsPath"
    }
    catch {
        throw "Failed to collect metrics: $_"
    }
}

# Task 5: Create Backup (if requested)
if ($CreateBackup) {
    Invoke-MaintenanceTask "Create Backup" {
        $backupScript = "${env:ProgramFiles}\RawrXD\recovery\backup\data_preservation.ps1"
        
        if (Test-Path $backupScript) {
            & $backupScript -Action "backup" -Compress
            return "Backup created successfully"
        } else {
            throw "Backup script not found"
        }
    }
}

# Task 6: Disk Space Check
Invoke-MaintenanceTask "Disk Space Check" {
    $disk = Get-PSDrive -Name C
    $freePercent = ($disk.Free / ($disk.Free + $disk.Used)) * 100
    
    if ($freePercent -lt 10) {
        throw "Low disk space: $([math]::Round($freePercent, 2))% free"
    }
    
    return "Disk space OK: $([math]::Round($freePercent, 2))% free ($([math]::Round($disk.Free / 1GB, 2)) GB)"
}

# Task 7: Memory Check
Invoke-MaintenanceTask "Memory Check" {
    $memory = Get-CimInstance -ClassName Win32_OperatingSystem
    $usedPercent = (($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100
    
    if ($usedPercent -gt 95) {
        throw "High memory usage: $([math]::Round($usedPercent, 2))%"
    }
    
    return "Memory OK: $([math]::Round($usedPercent, 2))% used"
}

# Finalize
$MaintenanceLog.EndTime = Get-Date -Format "o"
$MaintenanceLog.Duration = (Get-Date) - [DateTime]$MaintenanceLog.StartTime

# Save maintenance log
$logFile = "$LogPath\maintenance_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$MaintenanceLog | ConvertTo-Json -Depth 5 | Out-File $logFile

Write-MaintLog ""
Write-MaintLog "Maintenance Complete" $(if ($MaintenanceLog.Success) { "SUCCESS" } else { "WARNING" })
Write-MaintLog "Duration: $([math]::Round($MaintenanceLog.Duration.TotalMinutes, 2)) minutes"
Write-MaintLog "Log saved: $logFile"
Write-MaintLog "Tasks: $($MaintenanceLog.Tasks.Count) total, $(($MaintenanceLog.Tasks | Where-Object { $_.Status -eq "SUCCESS" }).Count) successful"

if (-not $MaintenanceLog.Success) {
    exit 1
}
