# RawrXD Log Rotator
# Manages log file rotation and archival

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Rotate", "Archive", "Clean", "Status", "Configure")]
    [string]$Action = "Rotate",
    
    [string]$LogPath = "logs",
    [int]$MaxSizeMB = 100,
    [int]$MaxAgeDays = 30,
    [int]$MaxFiles = 10,
    [string]$ArchivePath = "logs\archive",
    [switch]$Compress,
    [switch]$DryRun,
    [string]$ConfigFile = "log-rotator.config.json"
)

$ErrorActionPreference = "Stop"

$script:Stats = @{
    Rotated = 0
    Archived = 0
    Deleted = 0
    SpaceReclaimedMB = 0
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

function Initialize-LogRotator {
    Write-Status "Log Rotator initialized"
    Write-Status "Action: $Action"
    Write-Status "Log Path: $LogPath"
    
    if (-not (Test-Path $LogPath)) {
        Write-Warning "Log path does not exist: $LogPath"
        return $false
    }
    
    if ($Action -in @("Archive", "Rotate") -and -not (Test-Path $ArchivePath)) {
        if (-not $DryRun) {
            New-Item -ItemType Directory -Path $ArchivePath -Force | Out-Null
            Write-Status "Created archive directory: $ArchivePath"
        }
    }
    
    return $true
}

function Get-LogFiles {
    $logFiles = Get-ChildItem -Path $LogPath -Filter "*.log" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    
    return $logFiles
}

function Invoke-LogRotation {
    Write-Status "Rotating log files..."
    
    $logFiles = Get-LogFiles
    
    foreach ($file in $logFiles) {
        $fileSizeMB = [math]::Round($file.Length / 1MB, 2)
        $fileAge = (Get-Date) - $file.LastWriteTime
        
        $shouldRotate = $false
        $reason = ""
        
        if ($fileSizeMB -gt $MaxSizeMB) {
            $shouldRotate = $true
            $reason = "size ($fileSizeMB MB > $MaxSizeMB MB)"
        }
        elseif ($fileAge.Days -gt $MaxAgeDays) {
            $shouldRotate = $true
            $reason = "age ($($fileAge.Days) days > $MaxAgeDays days)"
        }
        
        if ($shouldRotate) {
            Write-Status "Rotating: $($file.Name) ($reason)"
            
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $newName = "$($file.BaseName)-$timestamp.log"
            $destination = Join-Path $ArchivePath $newName
            
            if ($DryRun) {
                Write-Status "Would rotate: $($file.FullName) -> $destination"
            } else {
                try {
                    Move-Item -Path $file.FullName -Destination $destination -Force
                    
                    if ($Compress) {
                        $zipPath = "$destination.zip"
                        Compress-Archive -Path $destination -DestinationPath $zipPath -Force
                        Remove-Item $destination -Force
                        Write-Success "Rotated and compressed: $newName.zip"
                    } else {
                        Write-Success "Rotated: $newName"
                    }
                    
                    $script:Stats.Rotated++
                    $script:Stats.SpaceReclaimedMB += $fileSizeMB
                }
                catch {
                    Write-Error "Failed to rotate $($file.Name): $_"
                }
            }
        }
    }
    
    # Create new empty log file if main log was rotated
    $mainLog = Join-Path $LogPath "rawrxd.log"
    if (-not (Test-Path $mainLog) -and -not $DryRun) {
        New-Item -ItemType File -Path $mainLog -Force | Out-Null
        Write-Status "Created new log file: $mainLog"
    }
}

function Invoke-LogArchival {
    Write-Status "Archiving old log files..."
    
    if (-not (Test-Path $ArchivePath)) {
        Write-Error "Archive path does not exist: $ArchivePath"
        return
    }
    
    $archiveFiles = Get-ChildItem -Path $ArchivePath -Filter "*.log" -File -ErrorAction SilentlyContinue
    
    foreach ($file in $archiveFiles) {
        $fileAge = (Get-Date) - $file.LastWriteTime
        
        if ($fileAge.Days -gt $MaxAgeDays) {
            Write-Status "Archiving old file: $($file.Name) ($($fileAge.Days) days old)"
            
            if ($DryRun) {
                Write-Status "Would archive: $($file.FullName)"
            } else {
                try {
                    $monthArchive = Join-Path $ArchivePath (Get-Date $file.LastWriteTime -Format "yyyy-MM")
                    
                    if (-not (Test-Path $monthArchive)) {
                        New-Item -ItemType Directory -Path $monthArchive -Force | Out-Null
                    }
                    
                    $destination = Join-Path $monthArchive $file.Name
                    Move-Item -Path $file.FullName -Destination $destination -Force
                    
                    $script:Stats.Archived++
                    Write-Success "Archived to: $monthArchive\$($file.Name)"
                }
                catch {
                    Write-Error "Failed to archive $($file.Name): $_"
                }
            }
        }
    }
}

function Invoke-LogCleanup {
    Write-Status "Cleaning up old log files..."
    
    if (-not (Test-Path $ArchivePath)) {
        return
    }
    
    # Clean up old archived files
    $cutoffDate = (Get-Date).AddDays(-$MaxAgeDays * 2)  # Keep for double the max age
    
    $oldFiles = Get-ChildItem -Path $ArchivePath -Recurse -File |
        Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    foreach ($file in $oldFiles) {
        Write-Status "Deleting old file: $($file.FullName)"
        
        if ($DryRun) {
            Write-Status "Would delete: $($file.FullName)"
        } else {
            try {
                $fileSizeMB = [math]::Round($file.Length / 1MB, 2)
                Remove-Item -Path $file.FullName -Force
                $script:Stats.Deleted++
                $script:Stats.SpaceReclaimedMB += $fileSizeMB
                Write-Success "Deleted: $($file.Name)"
            }
            catch {
                Write-Error "Failed to delete $($file.Name): $_"
            }
        }
    }
    
    # Clean up empty directories
    $emptyDirs = Get-ChildItem -Path $ArchivePath -Directory -Recurse |
        Where-Object { $_.GetFiles().Count -eq 0 -and $_.GetDirectories().Count -eq 0 }
    
    foreach ($dir in $emptyDirs) {
        if (-not $DryRun) {
            Remove-Item -Path $dir.FullName -Force
            Write-Status "Removed empty directory: $($dir.Name)"
        }
    }
}

function Get-LogStatus {
    Write-Status "Log directory status..."
    
    if (-not (Test-Path $LogPath)) {
        Write-Error "Log path does not exist: $LogPath"
        return
    }
    
    $logFiles = Get-LogFiles
    $totalSize = ($logFiles | Measure-Object -Property Length -Sum).Sum
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
    
    Write-Host ""
    Write-Host "Current Log Files:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    foreach ($file in $logFiles | Select-Object -First $MaxFiles) {
        $sizeMB = [math]::Round($file.Length / 1MB, 2)
        $age = (Get-Date) - $file.LastWriteTime
        $status = if ($sizeMB -gt $MaxSizeMB) { "OVERSIZE" } elseif ($age.Days -gt $MaxAgeDays) { "OLD" } else { "OK" }
        
        $color = switch ($status) {
            "OK" { "Green" }
            "OLD" { "Yellow" }
            "OVERSIZE" { "Red" }
        }
        
        Write-Host "  $($file.Name)" -NoNewline
        Write-Host " - $sizeMB MB, $($age.Days) days old [$status]" -ForegroundColor $color
    }
    
    if ($logFiles.Count -gt $MaxFiles) {
        Write-Host "  ... and $($logFiles.Count - $MaxFiles) more files" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Total files: $($logFiles.Count)"
    Write-Host "  Total size: $totalSizeMB MB"
    Write-Host "  Max size threshold: $MaxSizeMB MB"
    Write-Host "  Max age threshold: $MaxAgeDays days"
    
    # Archive status
    if (Test-Path $ArchivePath) {
        $archiveFiles = Get-ChildItem -Path $ArchivePath -Recurse -File
        $archiveSize = ($archiveFiles | Measure-Object -Property Length -Sum).Sum
        $archiveSizeMB = [math]::Round($archiveSize / 1MB, 2)
        Write-Host "  Archived files: $($archiveFiles.Count) ($archiveSizeMB MB)"
    }
}

function Export-Configuration {
    $config = @{
        LogPath = $LogPath
        ArchivePath = $ArchivePath
        MaxSizeMB = $MaxSizeMB
        MaxAgeDays = $MaxAgeDays
        MaxFiles = $MaxFiles
        Compress = $Compress.IsPresent
        Timestamp = Get-Date -Format "o"
    }
    
    $config | ConvertTo-Json -Depth 3 | Out-File $ConfigFile
    Write-Success "Configuration exported to: $ConfigFile"
}

function Show-Summary {
    if ($Action -in @("Rotate", "Archive", "Clean")) {
        Write-Host ""
        Write-Host "Log Rotation Summary" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host "Files rotated: $($script:Stats.Rotated)"
        Write-Host "Files archived: $($script:Stats.Archived)"
        Write-Host "Files deleted: $($script:Stats.Deleted)"
        Write-Host "Space reclaimed: $([math]::Round($script:Stats.SpaceReclaimedMB, 2)) MB"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Log Rotator" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Initialize-LogRotator)) {
        return
    }
    
    switch ($Action) {
        "Rotate" { 
            Invoke-LogRotation 
            Invoke-LogArchival
        }
        "Archive" { Invoke-LogArchival }
        "Clean" { Invoke-LogCleanup }
        "Status" { Get-LogStatus }
        "Configure" { Export-Configuration }
    }
    
    Show-Summary
    
    Write-Host ""
}

Main
