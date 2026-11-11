# RawrXD OMEGA-1 Log Rotator
# Manages log files with rotation and cleanup

param(
    [string]$LogDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1\logs",
    [int]$MaxLogSizeMB = 100,
    [int]$MaxLogFiles = 10,
    [int]$MaxLogAgeDays = 30,
    [switch]$Compress = $true,
    [switch]$WhatIf = $false
)

$ErrorActionPreference = 'Stop'

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "White" }
        default { "Gray" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

function Initialize-LogDirectory {
    if (!(Test-Path $LogDir)) {
        if (!$WhatIf) {
            New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
        }
        Write-Status "Created log directory: $LogDir" "OK"
    }
}

function Get-LogStats {
    $stats = @{
        TotalFiles = 0
        TotalSize = 0
        TotalSizeMB = 0
        OldestFile = $null
        NewestFile = $null
        FilesByExtension = @{}
    }
    
    if (Test-Path $LogDir) {
        $files = Get-ChildItem $LogDir -File -Recurse -ErrorAction SilentlyContinue
        
        $stats.TotalFiles = $files.Count
        $stats.TotalSize = ($files | Measure-Object -Property Length -Sum).Sum
        $stats.TotalSizeMB = [math]::Round($stats.TotalSize / 1MB, 2)
        
        if ($files.Count -gt 0) {
            $stats.OldestFile = ($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime
            $stats.NewestFile = ($files | Sort-Object CreationTime -Descending | Select-Object -First 1).CreationTime
            
            $files | Group-Object Extension | ForEach-Object {
                $stats.FilesByExtension[$_.Name] = @{
                    Count = $_.Count
                    Size = [math]::Round(($_.Group | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                }
            }
        }
    }
    
    return $stats
}

function Show-LogStats {
    Write-Header "Log Directory Statistics"
    
    Initialize-LogDirectory
    $stats = Get-LogStats
    
    Write-Status "Log directory: $LogDir" "INFO"
    Write-Status "Total files: $($stats.TotalFiles)" "INFO"
    Write-Status "Total size: $($stats.TotalSizeMB) MB" "INFO"
    
    if ($stats.OldestFile) {
        Write-Status "Oldest file: $($stats.OldestFile)" "INFO"
        Write-Status "Newest file: $($stats.NewestFile)" "INFO"
    }
    
    if ($stats.FilesByExtension.Count -gt 0) {
        Write-Host "`n  Files by type:" -ForegroundColor Gray
        foreach ($ext in $stats.FilesByExtension.GetEnumerator()) {
            Write-Host "    $($ext.Key): $($ext.Value.Count) files ($($ext.Value.Size) MB)" -ForegroundColor Gray
        }
    }
}

function Rotate-LargeLogs {
    Write-Header "Rotating Large Log Files"
    
    $largeFiles = Get-ChildItem $LogDir -File -Recurse | Where-Object { $_.Length -gt ($MaxLogSizeMB * 1MB) }
    
    if ($largeFiles.Count -eq 0) {
        Write-Status "No large log files found" "OK"
        return
    }
    
    Write-Status "Found $($largeFiles.Count) large file(s)" "WARN"
    
    foreach ($file in $largeFiles) {
        $sizeMB = [math]::Round($file.Length / 1MB, 2)
        Write-Status "Rotating: $($file.Name) ($sizeMB MB)" "INFO"
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $newName = "$($file.BaseName)_$timestamp$($file.Extension)"
        $newPath = Join-Path $file.DirectoryName $newName
        
        if ($WhatIf) {
            Write-Host "  [WhatIf] Would rename to: $newName" -ForegroundColor Gray
        } else {
            Move-Item $file.FullName $newPath -Force
            Write-Status "Rotated to: $newName" "OK"
        }
        
        if ($Compress) {
            $zipPath = "$newPath.zip"
            if ($WhatIf) {
                Write-Host "  [WhatIf] Would compress to: $zipPath" -ForegroundColor Gray
            } else {
                Compress-Archive -Path $newPath -DestinationPath $zipPath -Force
                Remove-Item $newPath -Force
                $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
                Write-Status "Compressed to: $zipSize MB" "OK"
            }
        }
    }
}

function Remove-OldLogs {
    Write-Header "Removing Old Log Files"
    
    $cutoffDate = (Get-Date).AddDays(-$MaxLogAgeDays)
    $oldFiles = Get-ChildItem $LogDir -File -Recurse | Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    if ($oldFiles.Count -eq 0) {
        Write-Status "No old log files found" "OK"
        return
    }
    
    $totalSize = ($oldFiles | Measure-Object -Property Length -Sum).Sum / 1MB
    
    Write-Status "Found $($oldFiles.Count) old file(s)" "WARN"
    Write-Status "Total size: $([math]::Round($totalSize, 2)) MB" "INFO"
    
    foreach ($file in $oldFiles) {
        Write-Host "  - $($file.Name) (last write: $($file.LastWriteTime))" -ForegroundColor Gray
    }
    
    $deleted = 0
    $freedSpace = 0
    
    foreach ($file in $oldFiles) {
        try {
            if ($WhatIf) {
                Write-Host "  [WhatIf] Would delete: $($file.Name)" -ForegroundColor Gray
            } else {
                $freedSpace += $file.Length
                Remove-Item $file.FullName -Force
                $deleted++
            }
        } catch {
            Write-Status "Failed to delete $($file.Name)" "WARN"
        }
    }
    
    if (!$WhatIf) {
        Write-Status "Deleted $deleted file(s), freed $([math]::Round($freedSpace / 1MB, 2)) MB" "OK"
    }
}

function Limit-LogFiles {
    Write-Header "Limiting Log File Count"
    
    $logFiles = Get-ChildItem $LogDir -File -Recurse | Sort-Object LastWriteTime -Descending
    
    if ($logFiles.Count -le $MaxLogFiles) {
        Write-Status "Log file count within limit ($($logFiles.Count)/$MaxLogFiles)" "OK"
        return
    }
    
    $filesToDelete = $logFiles | Select-Object -Skip $MaxLogFiles
    
    Write-Status "Found $($filesToDelete.Count) excess file(s)" "WARN"
    
    $deleted = 0
    foreach ($file in $filesToDelete) {
        try {
            if ($WhatIf) {
                Write-Host "  [WhatIf] Would delete: $($file.Name)" -ForegroundColor Gray
            } else {
                Remove-Item $file.FullName -Force
                $deleted++
            }
        } catch {
            Write-Status "Failed to delete $($file.Name)" "WARN"
        }
    }
    
    if (!$WhatIf) {
        Write-Status "Deleted $deleted excess file(s)" "OK"
    }
}

function Compress-OldLogs {
    Write-Header "Compressing Old Log Files"
    
    $uncompressedFiles = Get-ChildItem $LogDir -File -Recurse | Where-Object { $_.Extension -ne '.zip' -and $_.Extension -ne '.gz' }
    
    if ($uncompressedFiles.Count -eq 0) {
        Write-Status "No uncompressed files found" "OK"
        return
    }
    
    $compressed = 0
    $savedSpace = 0
    
    foreach ($file in $uncompressedFiles) {
        # Only compress files older than 7 days
        if ($file.LastWriteTime -lt (Get-Date).AddDays(-7)) {
            $zipPath = "$($file.FullName).zip"
            
            try {
                if ($WhatIf) {
                    Write-Host "  [WhatIf] Would compress: $($file.Name)" -ForegroundColor Gray
                } else {
                    $originalSize = $file.Length
                    Compress-Archive -Path $file.FullName -DestinationPath $zipPath -Force
                    Remove-Item $file.FullName -Force
                    $zipSize = (Get-Item $zipPath).Length
                    $savedSpace += ($originalSize - $zipSize)
                    $compressed++
                }
            } catch {
                Write-Status "Failed to compress $($file.Name)" "WARN"
            }
        }
    }
    
    if (!$WhatIf -and $compressed -gt 0) {
        Write-Status "Compressed $compressed file(s), saved $([math]::Round($savedSpace / 1MB, 2)) MB" "OK"
    }
}

# =============================================================================
# Main Execution
# =============================================================================
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Log Rotator                                                 ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "`n  [WHATIF MODE] No changes will be made`n" -ForegroundColor Yellow
}

Show-LogStats
Rotate-LargeLogs
Remove-OldLogs
Limit-LogFiles
if ($Compress) {
    Compress-OldLogs
}

Write-Host "`n  Final Statistics:" -ForegroundColor Cyan
$finalStats = Get-LogStats
Write-Status "Total files: $($finalStats.TotalFiles)" "INFO"
Write-Status "Total size: $($finalStats.TotalSizeMB) MB" "INFO"

Write-Host "`nLog rotation complete!`n" -ForegroundColor Cyan
