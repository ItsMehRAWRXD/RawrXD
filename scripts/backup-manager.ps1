# RawrXD Backup Manager
# Comprehensive backup and restore management

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Create", "Restore", "List", "Delete", "Schedule", "Verify")]
    [string]$Action = "Create",
    
    [string]$BackupName = "",
    [string]$BackupPath = "backups",
    [string[]]$Sources = @("models", "config", "data"),
    [string]$Destination = "local",  # local, s3, azure, gcs
    [switch]$Compress,
    [switch]$Encrypt,
    [string]$RetentionDays = 30,
    [switch]$FullBackup
)

$ErrorActionPreference = "Stop"

$script:BackupId = "backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$script:Results = @{
    Timestamp = Get-Date -Format "o"
    Action = $Action
    BackupId = $script:BackupId
    Status = "Pending"
    Files = @()
    Size = 0
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

function Initialize-Backup {
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    Write-Status "Backup Manager initialized"
    Write-Status "Action: $Action"
    Write-Status "Backup ID: $script:BackupId"
}

function Invoke-BackupCreate {
    Write-Status "Creating backup..."
    
    $backupDir = "$BackupPath\$script:BackupId"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    $manifest = @{
        BackupId = $script:BackupId
        Timestamp = Get-Date -Format "o"
        Sources = $Sources
        FullBackup = $FullBackup
        Files = @()
    }
    
    foreach ($source in $Sources) {
        if (-not (Test-Path $source)) {
            Write-Warning "Source not found: $source"
            continue
        }
        
        Write-Status "Backing up: $source"
        
        $sourceName = Split-Path $source -Leaf
        $targetPath = "$backupDir\$sourceName"
        
        if ((Get-Item $source) -is [System.IO.DirectoryInfo]) {
            Copy-Item -Recurse -Path $source -Destination $targetPath
        } else {
            Copy-Item -Path $source -Destination $targetPath
        }
        
        $fileInfo = Get-Item $targetPath
        $manifest.Files += @{
            Source = $source
            Destination = $targetPath
            Size = $fileInfo.Length
            Modified = $fileInfo.LastWriteTime
        }
        
        $script:Results.Size += $fileInfo.Length
    }
    
    # Save manifest
    $manifest | ConvertTo-Json -Depth 10 | Out-File "$backupDir\manifest.json"
    
    # Compress if requested
    if ($Compress) {
        Write-Status "Compressing backup..."
        $archivePath = "$BackupPath\$script:BackupId.zip"
        Compress-Archive -Path $backupDir -DestinationPath $archivePath -Force
        
        # Remove uncompressed directory
        Remove-Item -Recurse -Force $backupDir
        
        $script:Results.Files += $archivePath
        $script:Results.Size = (Get-Item $archivePath).Length
        
        Write-Success "Backup compressed: $archivePath"
    } else {
        $script:Results.Files += $backupDir
        Write-Success "Backup created: $backupDir"
    }
    
    # Upload to cloud if requested
    switch ($Destination) {
        "s3" { Upload-ToS3 -BackupPath $backupDir }
        "azure" { Upload-ToAzure -BackupPath $backupDir }
        "gcs" { Upload-ToGCS -BackupPath $backupDir }
    }
    
    # Cleanup old backups
    Invoke-BackupCleanup
}

function Upload-ToS3 {
    param([string]$BackupPath)
    
    Write-Status "Uploading to S3..."
    
    $bucket = $env:RAWRXD_S3_BUCKET
    if (-not $bucket) {
        Write-Error "S3 bucket not configured. Set RAWRXD_S3_BUCKET environment variable."
        return
    }
    
    $key = "rawrxd-backups/$script:BackupId.zip"
    
    aws s3 cp $BackupPath s3://$bucket/$key
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Uploaded to S3: s3://$bucket/$key"
    } else {
        Write-Error "S3 upload failed"
    }
}

function Upload-ToAzure {
    param([string]$BackupPath)
    
    Write-Status "Uploading to Azure Blob Storage..."
    
    $container = $env:RAWRXD_AZURE_CONTAINER
    if (-not $container) {
        Write-Error "Azure container not configured. Set RAWRXD_AZURE_CONTAINER environment variable."
        return
    }
    
    $blobName = "rawrxd-backups/$script:BackupId.zip"
    
    az storage blob upload --file $BackupPath --container-name $container --name $blobName
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Uploaded to Azure: $blobName"
    } else {
        Write-Error "Azure upload failed"
    }
}

function Upload-ToGCS {
    param([string]$BackupPath)
    
    Write-Status "Uploading to Google Cloud Storage..."
    
    $bucket = $env:RAWRXD_GCS_BUCKET
    if (-not $bucket) {
        Write-Error "GCS bucket not configured. Set RAWRXD_GCS_BUCKET environment variable."
        return
    }
    
    $objectName = "rawrxd-backups/$script:BackupId.zip"
    
    gsutil cp $BackupPath gs://$bucket/$objectName
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Uploaded to GCS: gs://$bucket/$objectName"
    } else {
        Write-Error "GCS upload failed"
    }
}

function Invoke-BackupRestore {
    if (-not $BackupName) {
        # List available backups
        $backups = Get-ChildItem $BackupPath -Filter "backup-*" | Sort-Object Name -Descending
        
        if ($backups.Count -eq 0) {
            Write-Error "No backups found"
            return
        }
        
        Write-Host "`nAvailable backups:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $backups.Count; $i++) {
            $size = [math]::Round((Get-Item $backups[$i].FullName).Length / 1MB, 2)
            Write-Host "  [$i] $($backups[$i].Name) (${size} MB)" -ForegroundColor White
        }
        
        $selection = Read-Host "`nSelect backup to restore (0-$($backups.Count - 1))"
        $BackupName = $backups[$selection].Name
    }
    
    $backupPath = "$BackupPath\$BackupName"
    
    if (-not (Test-Path $backupPath)) {
        Write-Error "Backup not found: $BackupName"
        return
    }
    
    Write-Status "Restoring from backup: $BackupName"
    
    # Extract if compressed
    if ($backupPath.EndsWith(".zip")) {
        $extractPath = "$env:TEMP\rawrxd-restore-$BackupName"
        Expand-Archive -Path $backupPath -DestinationPath $extractPath -Force
        $backupPath = $extractPath
    }
    
    # Load manifest
    $manifestPath = "$backupPath\manifest.json"
    if (Test-Path $manifestPath) {
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        
        foreach ($file in $manifest.Files) {
            Write-Status "Restoring: $($file.Source)"
            
            $targetDir = Split-Path $file.Source -Parent
            if ($targetDir -and -not (Test-Path $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
            
            Copy-Item -Path $file.Destination -Destination $file.Source -Force -Recurse
        }
    } else {
        # No manifest, restore everything
        Write-Status "No manifest found, restoring all files..."
        Get-ChildItem $backupPath | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination ".\" -Force -Recurse
        }
    }
    
    Write-Success "Restore complete"
}

function Invoke-BackupList {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Available Backups" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Path $BackupPath)) {
        Write-Host "No backups found" -ForegroundColor Gray
        return
    }
    
    $backups = Get-ChildItem $BackupPath -Filter "backup-*" | Sort-Object Name -Descending
    
    if ($backups.Count -eq 0) {
        Write-Host "No backups found" -ForegroundColor Gray
        return
    }
    
    foreach ($backup in $backups) {
        $size = [math]::Round((Get-Item $backup.FullName).Length / 1MB, 2)
        $date = $backup.CreationTime
        
        Write-Host "$($backup.Name)" -ForegroundColor White
        Write-Host "  Size: ${size} MB" -ForegroundColor Gray
        Write-Host "  Created: $($date.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        Write-Host ""
    }
}

function Invoke-BackupDelete {
    if (-not $BackupName) {
        Write-Error "Backup name required for deletion"
        return
    }
    
    $backupPath = "$BackupPath\$BackupName"
    
    if (-not (Test-Path $backupPath)) {
        Write-Error "Backup not found: $BackupName"
        return
    }
    
    $confirm = Read-Host "Are you sure you want to delete $BackupName? (y/N)"
    if ($confirm -ne "y") {
        Write-Status "Deletion cancelled"
        return
    }
    
    Remove-Item -Recurse -Force $backupPath
    Write-Success "Backup deleted: $BackupName"
}

function Invoke-BackupCleanup {
    Write-Status "Cleaning up old backups (retention: $RetentionDays days)..."
    
    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    $backups = Get-ChildItem $BackupPath -Filter "backup-*"
    
    $deleted = 0
    foreach ($backup in $backups) {
        if ($backup.CreationTime -lt $cutoffDate) {
            Remove-Item -Recurse -Force $backup.FullName
            $deleted++
        }
    }
    
    if ($deleted -gt 0) {
        Write-Success "Deleted $deleted old backup(s)"
    } else {
        Write-Status "No old backups to delete"
    }
}

function Invoke-BackupVerify {
    if (-not $BackupName) {
        Write-Error "Backup name required for verification"
        return
    }
    
    $backupPath = "$BackupPath\$BackupName"
    
    if (-not (Test-Path $backupPath)) {
        Write-Error "Backup not found: $BackupName"
        return
    }
    
    Write-Status "Verifying backup: $BackupName"
    
    # Check if compressed
    if ($backupPath.EndsWith(".zip")) {
        try {
            $test = Test-Path $backupPath
            $archive = [System.IO.Compression.ZipFile]::OpenRead($backupPath)
            $archive.Dispose()
            Write-Success "Archive integrity verified"
        }
        catch {
            Write-Error "Archive is corrupted: $_"
            return
        }
    }
    
    # Check manifest
    $manifestPath = "$backupPath\manifest.json"
    if (Test-Path $manifestPath) {
        try {
            $manifest = Get-Content $manifestPath | ConvertFrom-Json
            Write-Success "Manifest is valid"
            
            # Verify all files exist
            $missing = 0
            foreach ($file in $manifest.Files) {
                if (-not (Test-Path $file.Destination)) {
                    Write-Warning "Missing file: $($file.Destination)"
                    $missing++
                }
            }
            
            if ($missing -eq 0) {
                Write-Success "All files present"
            } else {
                Write-Error "$missing file(s) missing"
            }
        }
        catch {
            Write-Error "Manifest is corrupted: $_"
        }
    } else {
        Write-Warning "No manifest found"
    }
}

function Invoke-BackupSchedule {
    Write-Status "Creating scheduled backup task..."
    
    $taskName = "RawrXD-Backup"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$PSScriptRoot\backup-manager.ps1`" -Action Create -Sources $Sources -Compress"
    $trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force
    
    Write-Success "Scheduled task created: $taskName"
    Write-Status "Backups will run daily at 02:00"
}

# Main execution
function Main {
    Write-Host "RawrXD Backup Manager" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Backup
    
    switch ($Action) {
        "Create" { Invoke-BackupCreate }
        "Restore" { Invoke-BackupRestore }
        "List" { Invoke-BackupList }
        "Delete" { Invoke-BackupDelete }
        "Schedule" { Invoke-BackupSchedule }
        "Verify" { Invoke-BackupVerify }
    }
    
    Write-Host ""
}

Main
