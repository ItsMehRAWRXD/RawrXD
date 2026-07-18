# data_preservation.ps1
# Phase H.4 Batch 2/5: Data Preservation & Migration System

param(
    [string]$Action = "backup",
    [string]$SourceDir = "${env:ProgramFiles}\RawrXD",
    [string]$BackupRoot = "${env:ProgramData}\RawrXD\Backups",
    [string]$MigrationTarget = $null,
    [switch]$Compress,
    [switch]$Verify
)

$ErrorActionPreference = "Stop"

$PreserveConfig = @{
    ConfigFiles = @(
        "config\rawrxd.yaml",
        "config\models.yaml",
        "config\logging.yaml"
    )
    DataDirs = @(
        "data\models",
        "data\cache",
        "data\embeddings"
    )
    LogFiles = @(
        "logs\*.log",
        "logs\audit\*.json"
    )
    RegistryKeys = @(
        "HKLM\SOFTWARE\RawrXD",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD"
    )
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

function Backup-Configuration {
    param($BackupPath)
    
    Write-Log "Backing up configuration files..."
    $configBackup = Join-Path $BackupPath "config"
    New-Item -ItemType Directory -Path $configBackup -Force | Out-Null
    
    foreach ($file in $PreserveConfig.ConfigFiles) {
        $source = Join-Path $SourceDir $file
        if (Test-Path $source) {
            $dest = Join-Path $configBackup (Split-Path $file -Leaf)
            Copy-Item -Path $source -Destination $dest -Force
            Write-Log "  Backed up: $file"
        }
    }
    
    # Export registry settings
    $regFile = Join-Path $configBackup "registry.reg"
    foreach ($key in $PreserveConfig.RegistryKeys) {
        $keyName = $key.Replace('\', '_').Replace(':', '_')
        $keyFile = Join-Path $configBackup "$keyName.reg"
        reg export $key $keyFile /y 2>$null | Out-Null
    }
}

function Backup-Data {
    param($BackupPath)
    
    Write-Log "Backing up data directories..."
    $dataBackup = Join-Path $BackupPath "data"
    New-Item -ItemType Directory -Path $dataBackup -Force | Out-Null
    
    foreach ($dir in $PreserveConfig.DataDirs) {
        $source = Join-Path $SourceDir $dir
        if (Test-Path $source) {
            $dest = Join-Path $dataBackup (Split-Path $dir -Leaf)
            Copy-Item -Path $source -Destination $dest -Recurse -Force
            $size = (Get-ChildItem $source -Recurse | Measure-Object -Property Length -Sum).Sum
            Write-Log "  Backed up: $dir ($([math]::Round($size / 1MB, 2)) MB)"
        }
    }
}

function Backup-Logs {
    param($BackupPath)
    
    Write-Log "Backing up log files..."
    $logsBackup = Join-Path $BackupPath "logs"
    New-Item -ItemType Directory -Path $logsBackup -Force | Out-Null
    
    foreach ($pattern in $PreserveConfig.LogFiles) {
        $files = Get-ChildItem -Path (Join-Path $SourceDir $pattern) -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $dest = Join-Path $logsBackup $file.Name
            Copy-Item -Path $file.FullName -Destination $dest -Force
            Write-Log "  Backed up: $($file.Name)"
        }
    }
}

function Invoke-FullBackup {
    param($Version)
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupName = "v$Version-$timestamp"
    $backupPath = Join-Path $BackupRoot $backupName
    
    Write-Log "Creating full backup: $backupName"
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    
    # Create manifest
    $manifest = @{
        Version = $Version
        Timestamp = Get-Date -Format "o"
        SourceDir = $SourceDir
        BackupType = "Full"
    }
    
    # Backup components
    Backup-Configuration -BackupPath $backupPath
    Backup-Data -BackupPath $backupPath
    Backup-Logs -BackupPath $backupPath
    
    # Save manifest
    $manifest | ConvertTo-Json | Out-File (Join-Path $backupPath "manifest.json")
    
    # Compress if requested
    if ($Compress) {
        Write-Log "Compressing backup..."
        $zipPath = "$backupPath.zip"
        Compress-Archive -Path $backupPath -DestinationPath $zipPath -Force
        Remove-Item -Path $backupPath -Recurse -Force
        Write-Log "Backup compressed: $zipPath"
        
        # Generate checksum
        $hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
        $hash | Out-File "$zipPath.sha256"
        Write-Log "Checksum: $hash"
    }
    
    Write-Log "Backup completed: $backupName" "SUCCESS"
    return $backupPath
}

function Invoke-Restore {
    param($BackupPath)
    
    Write-Log "Restoring from backup: $BackupPath"
    
    # Verify backup exists
    if (-not (Test-Path $BackupPath)) {
        Write-Log "Backup not found: $BackupPath" "ERROR"
        return $false
    }
    
    # Load manifest
    $manifestPath = Join-Path $BackupPath "manifest.json"
    if (Test-Path $manifestPath) {
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        Write-Log "Restoring backup from v$($manifest.Version)"
    }
    
    # Restore configuration
    $configBackup = Join-Path $BackupPath "config"
    if (Test-Path $configBackup) {
        Write-Log "Restoring configuration..."
        Copy-Item -Path "$configBackup\*" -Destination "$SourceDir\config" -Recurse -Force
    }
    
    # Restore data
    $dataBackup = Join-Path $BackupPath "data"
    if (Test-Path $dataBackup) {
        Write-Log "Restoring data..."
        Copy-Item -Path "$dataBackup\*" -Destination "$SourceDir\data" -Recurse -Force
    }
    
    # Restore registry
    $regFiles = Get-ChildItem -Path $configBackup -Filter "*.reg" -ErrorAction SilentlyContinue
    foreach ($regFile in $regFiles) {
        Write-Log "Restoring registry: $($regFile.Name)"
        reg import $regFile.FullName 2>$null | Out-Null
    }
    
    Write-Log "Restore completed" "SUCCESS"
    return $true
}

function Invoke-Migration {
    param($FromVersion, $ToVersion)
    
    Write-Log "Migrating data from v$FromVersion to v$ToVersion..."
    
    # Migration rules
    $migrations = @{
        "1.0.0_to_1.1.0" = {
            # Example: Add new config field
            $configPath = Join-Path $SourceDir "config\rawrxd.yaml"
            if (Test-Path $configPath) {
                $config = Get-Content $configPath -Raw
                if ($config -notmatch "new_feature:") {
                    Add-Content -Path $configPath -Value "`nnew_feature:`n  enabled: true`n"
                    Write-Log "Migrated config for v1.1.0"
                }
            }
        }
    }
    
    $migrationKey = "${FromVersion}_to_${ToVersion}"
    if ($migrations.ContainsKey($migrationKey)) {
        & $migrations[$migrationKey]
        Write-Log "Migration completed" "SUCCESS"
    }
    else {
        Write-Log "No migration required for this version change"
    }
}

# Main execution
switch ($Action.ToLower()) {
    "backup" {
        $version = (Get-Item (Join-Path $SourceDir "RawrXD.exe")).VersionInfo.ProductVersion
        Invoke-FullBackup -Version $version
    }
    "restore" {
        if (-not $MigrationTarget) {
            Write-Log "MigrationTarget required for restore" "ERROR"
            exit 1
        }
        Invoke-Restore -BackupPath $MigrationTarget
    }
    "migrate" {
        if (-not $MigrationTarget) {
            Write-Log "MigrationTarget required for migrate" "ERROR"
            exit 1
        }
        Invoke-Migration -FromVersion $MigrationTarget -ToVersion (Get-CurrentVersion)
    }
    default {
        Write-Log "Unknown action: $Action" "ERROR"
        Write-Log "Valid actions: backup, restore, migrate"
        exit 1
    }
}
