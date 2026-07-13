# RawrXD Backup Manager
# Automated backup with compression, encryption, and retention policies

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Full", "Incremental", "Differential", "ConfigOnly")]
    [string]$BackupType = "Full",
    
    [string]$BackupPath = "disaster-recovery/backups/storage",
    [string]$EncryptionKey,
    [int]$RetentionDays = 30,
    [switch]$Verify,
    [switch]$UploadToRemote,
    [string]$RemoteEndpoint,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    BackupType = $BackupType
    BackupPath = $BackupPath
    RetentionDays = $RetentionDays
    CompressionLevel = "Optimal"
    ExcludePaths = @(
        "*.tmp",
        "*.log",
        "logs/*",
        "tests/*",
        "benchmarks/*",
        ".git/*"
    )
    CriticalPaths = @(
        "security/",
        "monitoring/",
        "docs/",
        "tests/",
        ".github/"
    )
}

# Backup metadata
$script:BackupMetadata = @{
    backup_id = [Guid]::NewGuid().ToString()
    timestamp = Get-Date -Format "o"
    type = $BackupType
    version = "1.0.0"
    hostname = $env:COMPUTERNAME
    user = $env:USERNAME
    paths = @()
    files_count = 0
    size_bytes = 0
    compressed_size_bytes = 0
    checksum = ""
    encryption = $null
    verification = @{
        verified = $false
        verified_at = $null
        checksum_valid = $false
    }
}

function Initialize-BackupEnvironment {
    Write-Host "Initializing backup environment..." -ForegroundColor Cyan
    
    # Create backup directory
    if (-not (Test-Path $script:Config.BackupPath)) {
        New-Item -ItemType Directory -Path $script:Config.BackupPath -Force | Out-Null
    }
    
    # Create dated subdirectory
    $script:BackupDir = Join-Path $script:Config.BackupPath (Get-Date -Format "yyyyMMdd-HHmmss")
    New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
    
    Write-Host "  Backup directory: $script:BackupDir" -ForegroundColor Gray
    
    # Check disk space
    $drive = (Get-Item $script:Config.BackupPath).PSDrive
    $freeSpace = $drive.Free
    $requiredSpace = 1GB  # Estimate
    
    if ($freeSpace -lt $requiredSpace) {
        throw "Insufficient disk space. Required: $([math]::Round($requiredSpace/1GB, 2)) GB, Available: $([math]::Round($freeSpace/1GB, 2)) GB"
    }
    
    Write-Host "  Free space: $([math]::Round($freeSpace/1GB, 2)) GB" -ForegroundColor Gray
}

function Backup-CriticalPaths {
    Write-Host "`nBacking up critical paths..." -ForegroundColor Cyan
    
    foreach ($path in $script:Config.CriticalPaths) {
        if (Test-Path $path) {
            Write-Host "  Processing: $path" -ForegroundColor Gray
            
            $destPath = Join-Path $script:BackupDir $path
            $destDir = Split-Path $destPath -Parent
            
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            if ($DryRun) {
                Write-Host "    [DRY RUN] Would copy $path to $destPath" -ForegroundColor Yellow
            } else {
                # Use robocopy for reliable copying with exclusions
                $excludeArgs = $script:Config.ExcludePaths -join " "
                $robocopyArgs = @(
                    $path,
                    $destPath,
                    "/MIR",
                    "/R:3",
                    "/W:5",
                    "/MT:8",
                    "/XD", ($script:Config.ExcludePaths -join " "),
                    "/NP",
                    "/NFL",
                    "/NDL"
                )
                
                $result = Start-Process -FilePath "robocopy" -ArgumentList $robocopyArgs -Wait -PassThru -WindowStyle Hidden
                
                if ($result.ExitCode -gt 7) {  # Robocopy exit codes > 7 indicate errors
                    Write-Warning "Robocopy completed with exit code: $($result.ExitCode)"
                }
            }
            
            $script:BackupMetadata.paths += $path
        } else {
            Write-Warning "  Path not found: $path"
        }
    }
}

function Backup-Registry {
    Write-Host "`nBacking up registries..." -ForegroundColor Cyan
    
    $registries = @(
        @{ Source = "security/phase_g1_hotpatch/registry/patch_registry.json"; Dest = "registries/patch_registry.json" },
        @{ Source = "security/phase_h_enterprise_security/rbac/rbac_config.json"; Dest = "registries/rbac_config.json" }
    )
    
    foreach ($registry in $registries) {
        if (Test-Path $registry.Source) {
            $destPath = Join-Path $script:BackupDir $registry.Dest
            $destDir = Split-Path $destPath -Parent
            
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            if ($DryRun) {
                Write-Host "  [DRY RUN] Would copy $($registry.Source)" -ForegroundColor Yellow
            } else {
                Copy-Item $registry.Source $destPath -Force
                Write-Host "  ✓ Backed up: $($registry.Source)" -ForegroundColor Green
            }
        }
    }
}

function Backup-Configuration {
    Write-Host "`nBacking up configuration..." -ForegroundColor Cyan
    
    $configFiles = @(
        "monitoring/prometheus/prometheus.yml",
        "monitoring/alerts/alertmanager.yml",
        "tests/pester.config.json",
        ".github/workflows/*.yml"
    )
    
    foreach ($config in $configFiles) {
        $files = Get-ChildItem -Path $config -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $relativePath = $file.FullName.Substring((Get-Location).Path.Length + 1)
            $destPath = Join-Path $script:BackupDir $relativePath
            $destDir = Split-Path $destPath -Parent
            
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            if ($DryRun) {
                Write-Host "  [DRY RUN] Would copy $relativePath" -ForegroundColor Yellow
            } else {
                Copy-Item $file.FullName $destPath -Force
                Write-Host "  ✓ Backed up: $relativePath" -ForegroundColor Green
            }
        }
    }
}

function Compress-Backup {
    Write-Host "`nCompressing backup..." -ForegroundColor Cyan
    
    $archiveName = "rawrxd-backup-$($script:BackupMetadata.backup_id).zip"
    $archivePath = Join-Path $script:Config.BackupPath $archiveName
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would create archive: $archivePath" -ForegroundColor Yellow
    } else {
        # Calculate size before compression
        $sizeBefore = (Get-ChildItem $script:BackupDir -Recurse | Measure-Object -Property Length -Sum).Sum
        
        # Create archive
        Compress-Archive -Path "$script:BackupDir\*" -DestinationPath $archivePath -CompressionLevel $script:Config.CompressionLevel
        
        # Calculate compression ratio
        $sizeAfter = (Get-Item $archivePath).Length
        $compressionRatio = [math]::Round(($sizeBefore - $sizeAfter) / $sizeBefore * 100, 2)
        
        $script:BackupMetadata.size_bytes = $sizeBefore
        $script:BackupMetadata.compressed_size_bytes = $sizeAfter
        
        Write-Host "  Original size: $([math]::Round($sizeBefore/1MB, 2)) MB" -ForegroundColor Gray
        Write-Host "  Compressed size: $([math]::Round($sizeAfter/1MB, 2)) MB" -ForegroundColor Gray
        Write-Host "  Compression ratio: $compressionRatio%" -ForegroundColor Green
        
        # Remove uncompressed backup
        Remove-Item $script:BackupDir -Recurse -Force
        
        # Update backup directory to archive path
        $script:BackupDir = $archivePath
    }
}

function Protect-Backup {
    Write-Host "`nProtecting backup..." -ForegroundColor Cyan
    
    if ($EncryptionKey) {
        Write-Host "  Encrypting backup..." -ForegroundColor Gray
        
        if ($DryRun) {
            Write-Host "  [DRY RUN] Would encrypt backup" -ForegroundColor Yellow
        } else {
            # Generate AES key from password
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptionKey.PadRight(32))
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $keyBytes
            $aes.GenerateIV()
            
            # Read file
            $fileBytes = [System.IO.File]::ReadAllBytes($script:BackupDir)
            
            # Encrypt
            $encryptor = $aes.CreateEncryptor()
            $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)
            
            # Write encrypted file
            $encryptedPath = "$script:BackupDir.encrypted"
            [System.IO.File]::WriteAllBytes($encryptedPath, $aes.IV + $encryptedBytes)
            
            # Remove unencrypted file
            Remove-Item $script:BackupDir -Force
            $script:BackupDir = $encryptedPath
            
            $script:BackupMetadata.encryption = @{
                algorithm = "AES-256"
                iv = [Convert]::ToBase64String($aes.IV)
            }
            
            Write-Host "  ✓ Backup encrypted" -ForegroundColor Green
        }
    }
    
    # Calculate checksum
    if (-not $DryRun) {
        Write-Host "  Calculating checksum..." -ForegroundColor Gray
        $hash = Get-FileHash $script:BackupDir -Algorithm SHA256
        $script:BackupMetadata.checksum = $hash.Hash
        Write-Host "  ✓ Checksum: $($hash.Hash)" -ForegroundColor Green
    }
}

function Test-Backup {
    Write-Host "`nVerifying backup..." -ForegroundColor Cyan
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would verify backup" -ForegroundColor Yellow
        return
    }
    
    # Verify file exists and is readable
    if (-not (Test-Path $script:BackupDir)) {
        throw "Backup file not found: $script:BackupDir"
    }
    
    # Verify checksum
    $currentHash = Get-FileHash $script:BackupDir -Algorithm SHA256
    if ($currentHash.Hash -ne $script:BackupMetadata.checksum) {
        throw "Backup checksum mismatch!"
    }
    
    # Try to open archive (basic integrity check)
    try {
        if ($script:BackupDir.EndsWith(".encrypted")) {
            Write-Host "  Encrypted backup - skipping archive test" -ForegroundColor Gray
        } else {
            $archive = [System.IO.Compression.ZipFile]::OpenRead($script:BackupDir)
            $entries = $archive.Entries.Count
            $archive.Dispose()
            Write-Host "  Archive contains $entries entries" -ForegroundColor Gray
        }
        
        $script:BackupMetadata.verification.verified = $true
        $script:BackupMetadata.verification.verified_at = Get-Date -Format "o"
        $script:BackupMetadata.verification.checksum_valid = $true
        
        Write-Host "  ✓ Backup verified successfully" -ForegroundColor Green
    }
    catch {
        throw "Backup verification failed: $_"
    }
}

function Send-RemoteBackup {
    Write-Host "`nUploading to remote endpoint..." -ForegroundColor Cyan
    
    if (-not $RemoteEndpoint) {
        Write-Warning "Remote endpoint not specified, skipping upload"
        return
    }
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would upload to: $RemoteEndpoint" -ForegroundColor Yellow
        return
    }
    
    try {
        # Upload using HTTP POST
        $headers = @{
            "Content-Type" = "application/octet-stream"
            "X-Backup-ID" = $script:BackupMetadata.backup_id
        }
        
        $response = Invoke-RestMethod -Uri $RemoteEndpoint -Method Post -InFile $script:BackupDir -Headers $headers
        Write-Host "  ✓ Uploaded successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to upload backup: $_"
    }
}

function Remove-OldBackups {
    Write-Host "`nCleaning up old backups..." -ForegroundColor Cyan
    
    $cutoffDate = (Get-Date).AddDays(-$script:Config.RetentionDays)
    $backups = Get-ChildItem -Path $script:Config.BackupPath -Filter "rawrxd-backup-*.zip*"
    
    $removed = 0
    foreach ($backup in $backups) {
        if ($backup.CreationTime -lt $cutoffDate) {
            if ($DryRun) {
                Write-Host "  [DRY RUN] Would remove: $($backup.Name)" -ForegroundColor Yellow
            } else {
                Remove-Item $backup.FullName -Force
                Write-Host "  Removed: $($backup.Name)" -ForegroundColor Gray
                $removed++
            }
        }
    }
    
    Write-Host "  Removed $removed old backups" -ForegroundColor Green
}

function Save-BackupMetadata {
    Write-Host "`nSaving backup metadata..." -ForegroundColor Cyan
    
    $metadataPath = "$script:BackupDir.json"
    $script:BackupMetadata | ConvertTo-Json -Depth 10 | Out-File $metadataPath
    
    Write-Host "  Metadata saved: $metadataPath" -ForegroundColor Green
}

# Main execution
function Invoke-BackupManager {
    Write-Host "RawrXD Backup Manager" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host "Backup Type: $BackupType" -ForegroundColor Yellow
    Write-Host "Backup ID: $($script:BackupMetadata.backup_id)" -ForegroundColor Yellow
    if ($DryRun) { Write-Host "*** DRY RUN MODE ***" -ForegroundColor Magenta }
    Write-Host ""
    
    try {
        Initialize-BackupEnvironment
        Backup-CriticalPaths
        Backup-Registry
        Backup-Configuration
        Compress-Backup
        Protect-Backup
        
        if ($Verify) {
            Test-Backup
        }
        
        if ($UploadToRemote) {
            Send-RemoteBackup
        }
        
        Remove-OldBackups
        Save-BackupMetadata
        
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Backup completed successfully!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Backup ID: $($script:BackupMetadata.backup_id)" -ForegroundColor White
        Write-Host "Location: $script:BackupDir" -ForegroundColor White
        if ($script:BackupMetadata.compressed_size_bytes -gt 0) {
            Write-Host "Size: $([math]::Round($script:BackupMetadata.compressed_size_bytes/1MB, 2)) MB" -ForegroundColor White
        }
        Write-Host "========================================" -ForegroundColor Green
    }
    catch {
        Write-Error "Backup failed: $_"
        exit 1
    }
}

# Run backup
Invoke-BackupManager
