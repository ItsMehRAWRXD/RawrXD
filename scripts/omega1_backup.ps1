# RawrXD OMEGA-1 Backup & Restore
# Manages configuration and data backups

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("backup", "restore", "list", "clean")]
    [string]$Action = "list",
    
    [string]$BackupDir = "$env:USERPROFILE\RawrXD\Backups",
    [string]$InstallDir = "$env:LOCALAPPDATA\RawrXD\OMEGA1",
    [string]$BackupName = "",
    [switch]$IncludeModels = $false,
    [switch]$Compress = $true
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

function Initialize-BackupDirectory {
    if (!(Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        Write-Status "Created backup directory: $BackupDir" "OK"
    }
}

function Get-BackupInfo {
    param($Path)
    
    $info = @{}
    $item = Get-Item $Path -ErrorAction SilentlyContinue
    
    if ($item) {
        $info.Name = $item.Name
        $info.Size = $item.Length
        $info.SizeMB = [math]::Round($item.Length / 1MB, 2)
        $info.Created = $item.CreationTime
        $info.Type = if ($item.Extension -eq ".zip") { "Compressed" } else { "Directory" }
    }
    
    return $info
}

function New-Backup {
    Write-Header "Creating Backup"
    
    Initialize-BackupDirectory
    
    if (!(Test-Path $InstallDir)) {
        Write-Status "Installation directory not found: $InstallDir" "FAIL"
        return
    }
    
    if ([string]::IsNullOrEmpty($BackupName)) {
        $BackupName = "RawrXD_OMEGA1_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    
    $backupPath = Join-Path $BackupDir $BackupName
    
    Write-Status "Backup name: $BackupName" "INFO"
    Write-Status "Source: $InstallDir" "INFO"
    
    New-Item -ItemType Directory -Force -Path $backupPath | Out-Null
    
    # Backup configuration
    $configSource = Join-Path $InstallDir "config"
    if (Test-Path $configSource) {
        Copy-Item $configSource (Join-Path $backupPath "config") -Recurse -Force
        Write-Status "Backed up: configuration" "OK"
    }
    
    # Backup logs
    $logsSource = Join-Path $InstallDir "logs"
    if (Test-Path $logsSource) {
        $logsDest = Join-Path $backupPath "logs"
        New-Item -ItemType Directory -Force -Path $logsDest | Out-Null
        Get-ChildItem $logsSource -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | ForEach-Object {
            Copy-Item $_.FullName $logsDest -Force
        }
        Write-Status "Backed up: recent logs" "OK"
    }
    
    if ($IncludeModels) {
        $modelsSource = Join-Path $InstallDir "models"
        if (Test-Path $modelsSource) {
            Copy-Item $modelsSource (Join-Path $backupPath "models") -Recurse -Force
            Write-Status "Backed up: models" "OK"
        }
    }
    
    if ($Compress) {
        $zipPath = "$backupPath.zip"
        Compress-Archive -Path $backupPath -DestinationPath $zipPath -Force
        Remove-Item $backupPath -Recurse -Force
        $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Write-Status "Backup created: $zipPath ($zipSize MB)" "OK"
    } else {
        $backupSize = [math]::Round((Get-ChildItem $backupPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
        Write-Status "Backup created: $backupPath ($backupSize MB)" "OK"
    }
}

function Restore-Backup {
    Write-Header "Restoring Backup"
    
    if ([string]::IsNullOrEmpty($BackupName)) {
        Write-Status "Backup name required" "FAIL"
        return
    }
    
    $backupPath = Join-Path $BackupDir $BackupName
    $zipPath = "$backupPath.zip"
    
    if (Test-Path $zipPath) {
        $extractPath = Join-Path $env:TEMP "RawrXD_Restore_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        $backupPath = Join-Path $extractPath $BackupName
    } elseif (!(Test-Path $backupPath)) {
        Write-Status "Backup not found: $BackupName" "FAIL"
        return
    }
    
    Write-Host "`n  ⚠️  This will overwrite existing configuration!" -ForegroundColor Yellow
    $confirm = Read-Host "  Continue? (yes/N)"
    if ($confirm -ne "yes") {
        Write-Status "Restore cancelled" "INFO"
        return
    }
    
    # Restore components
    if (Test-Path (Join-Path $backupPath "config")) {
        $configDest = Join-Path $InstallDir "config"
        if (Test-Path $configDest) { Remove-Item $configDest -Recurse -Force }
        Copy-Item (Join-Path $backupPath "config") $configDest -Recurse -Force
        Write-Status "Restored: configuration" "OK"
    }
    
    Write-Status "Restore completed" "OK"
}

function Show-BackupList {
    Write-Header "Available Backups"
    
    Initialize-BackupDirectory
    
    $backups = Get-ChildItem $BackupDir | Where-Object { $_.Name -match "RawrXD_OMEGA1" -or $_.Extension -eq ".zip" }
    
    if ($backups.Count -eq 0) {
        Write-Status "No backups found" "WARN"
        return
    }
    
    $index = 1
    foreach ($backup in $backups) {
        $info = Get-BackupInfo $backup.FullName
        Write-Host "  [$index] $($info.Name) - $($info.SizeMB) MB ($($info.Created))" -ForegroundColor White
        $index++
    }
}

function Remove-OldBackups {
    Write-Header "Cleaning Up Old Backups"
    
    $cutoffDate = (Get-Date).AddDays(-30)
    $oldBackups = Get-ChildItem $BackupDir | Where-Object { $_.CreationTime -lt $cutoffDate }
    
    if ($oldBackups.Count -eq 0) {
        Write-Status "No old backups" "OK"
        return
    }
    
    $oldBackups | ForEach-Object { Remove-Item $_.FullName -Recurse -Force }
    Write-Status "Deleted $($oldBackups.Count) old backup(s)" "OK"
}

# Main
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Backup & Restore                                            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

switch ($Action) {
    "backup" { New-Backup }
    "restore" { Restore-Backup }
    "list" { Show-BackupList }
    "clean" { Remove-OldBackups }
}

Write-Host "`nBackup/Restore complete!`n" -ForegroundColor Cyan
