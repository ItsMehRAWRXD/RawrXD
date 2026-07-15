# RawrXD Recovery Procedures
# Automated recovery from various disaster scenarios

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Full", "Partial", "Registry", "Config", "PointInTime")]
    [string]$RecoveryType,
    
    [string]$BackupPath,
    [string]$EncryptionKey,
    [string]$TargetPath = ".",
    [datetime]$PointInTime,
    [switch]$ValidateOnly,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Recovery metadata
$script:RecoveryLog = @{
    recovery_id = [Guid]::NewGuid().ToString()
    started_at = Get-Date -Format "o"
    type = $RecoveryType
    backup_path = $BackupPath
    target_path = $TargetPath
    steps = @()
    status = "in_progress"
}

function Write-RecoveryLog {
    param([string]$Step, [string]$Status, [string]$Details = "")
    
    $script:RecoveryLog.steps += @{
        step = $Step
        status = $Status
        timestamp = Get-Date -Format "o"
        details = $Details
    }
    
    $color = switch ($Status) {
        "success" { "Green" }
        "error" { "Red" }
        "warning" { "Yellow" }
        "info" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Step" -ForegroundColor $color
    if ($Details) {
        Write-Host "  $Details" -ForegroundColor Gray
    }
}

function Initialize-RecoveryEnvironment {
    Write-RecoveryLog -Step "Initialize Recovery Environment" -Status "info"
    
    # Verify backup exists
    if (-not (Test-Path $BackupPath)) {
        throw "Backup not found: $BackupPath"
    }
    
    # Load backup metadata
    $metadataPath = "$BackupPath.json"
    if (Test-Path $metadataPath) {
        $script:BackupMetadata = Get-Content $metadataPath | ConvertFrom-Json
        Write-RecoveryLog -Step "Loaded Backup Metadata" -Status "success" -Details "Backup ID: $($script:BackupMetadata.backup_id)"
    }
    
    # Create recovery directory
    $script:RecoveryDir = Join-Path $TargetPath ".recovery-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Path $script:RecoveryDir -Force | Out-Null
    
    Write-RecoveryLog -Step "Recovery Directory Created" -Status "success" -Details $script:RecoveryDir
}

function Restore-FromBackup {
    Write-RecoveryLog -Step "Restore from Backup" -Status "info"
    
    $isEncrypted = $BackupPath.EndsWith(".encrypted")
    $archivePath = $BackupPath
    
    # Decrypt if needed
    if ($isEncrypted) {
        if (-not $EncryptionKey) {
            throw "Encryption key required for encrypted backup"
        }
        
        Write-RecoveryLog -Step "Decrypting Backup" -Status "info"
        
        $encryptedBytes = [System.IO.File]::ReadAllBytes($BackupPath)
        $iv = $encryptedBytes[0..15]
        $cipherText = $encryptedBytes[16..($encryptedBytes.Length - 1)]
        
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptionKey.PadRight(32))
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $keyBytes
        $aes.IV = $iv
        
        $decryptor = $aes.CreateDecryptor()
        $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
        
        $archivePath = "$script:RecoveryDir\decrypted-backup.zip"
        [System.IO.File]::WriteAllBytes($archivePath, $decryptedBytes)
        
        Write-RecoveryLog -Step "Backup Decrypted" -Status "success"
    }
    
    # Extract archive
    Write-RecoveryLog -Step "Extracting Archive" -Status "info"
    Expand-Archive -Path $archivePath -DestinationPath $script:RecoveryDir -Force
    Write-RecoveryLog -Step "Archive Extracted" -Status "success"
    
    return $script:RecoveryDir
}

function Invoke-FullRecovery {
    Write-RecoveryLog -Step "Starting Full Recovery" -Status "info"
    
    # Restore all components
    $components = @(
        "security",
        "monitoring",
        "docs",
        "tests",
        ".github"
    )
    
    foreach ($component in $components) {
        $source = Join-Path $script:RecoveryDir $component
        if (Test-Path $source) {
            $dest = Join-Path $TargetPath $component
            
            # Backup current state first
            if (Test-Path $dest) {
                $backupName = "$component-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                Rename-Item $dest $backupName -Force
                Write-RecoveryLog -Step "Backed up current $component" -Status "success"
            }
            
            # Restore from backup
            Copy-Item $source $dest -Recurse -Force
            Write-RecoveryLog -Step "Restored $component" -Status "success"
        }
    }
    
    # Restore registries
    Restore-Registries
    
    Write-RecoveryLog -Step "Full Recovery Complete" -Status "success"
}

function Invoke-PartialRecovery {
    param([string[]]$Components)
    
    Write-RecoveryLog -Step "Starting Partial Recovery" -Status "info" -Details "Components: $($Components -join ', ')"
    
    foreach ($component in $Components) {
        $source = Join-Path $script:RecoveryDir $component
        if (Test-Path $source) {
            $dest = Join-Path $TargetPath $component
            
            if (Test-Path $dest) {
                $backupName = "$component-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                Rename-Item $dest $backupName -Force
            }
            
            Copy-Item $source $dest -Recurse -Force
            Write-RecoveryLog -Step "Restored $component" -Status "success"
        } else {
            Write-RecoveryLog -Step "Component not found in backup" -Status "warning" -Details $component
        }
    }
}

function Restore-Registries {
    Write-RecoveryLog -Step "Restoring Registries" -Status "info"
    
    $registries = @(
        @{ Source = "registries/patch_registry.json"; Dest = "security/phase_g1_hotpatch/registry/patch_registry.json" },
        @{ Source = "registries/rbac_config.json"; Dest = "security/phase_h_enterprise_security/rbac/rbac_config.json" }
    )
    
    foreach ($registry in $registries) {
        $source = Join-Path $script:RecoveryDir $registry.Source
        $dest = Join-Path $TargetPath $registry.Dest
        
        if (Test-Path $source) {
            $destDir = Split-Path $dest -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            
            Copy-Item $source $dest -Force
            Write-RecoveryLog -Step "Restored registry" -Status "success" -Details $registry.Dest
        }
    }
}

function Restore-Configuration {
    Write-RecoveryLog -Step "Restoring Configuration" -Status "info"
    
    $configFiles = Get-ChildItem -Path "$script:RecoveryDir\monitoring" -Filter "*.yml" -Recurse
    foreach ($file in $configFiles) {
        $relativePath = $file.FullName.Substring($script:RecoveryDir.Length + 1)
        $dest = Join-Path $TargetPath $relativePath
        
        if (Test-Path (Split-Path $dest -Parent)) {
            Copy-Item $file.FullName $dest -Force
            Write-RecoveryLog -Step "Restored config" -Status "success" -Details $relativePath
        }
    }
}

function Test-Recovery {
    Write-RecoveryLog -Step "Validating Recovery" -Status "info"
    
    $tests = @(
        @{ Name = "Security Wrapper"; Path = "security/integration/secure_hotpatch.ps1"; Test = { Test-Path $args[0] } },
        @{ Name = "RBAC Manager"; Path = "security/phase_h_enterprise_security/rbac/rbac_manager.ps1"; Test = { Test-Path $args[0] } },
        @{ Name = "Patch Registry"; Path = "security/phase_g1_hotpatch/registry/patch_registry.json"; Test = { Test-Path $args[0] } },
        @{ Name = "Health Check"; Path = "monitoring/scripts/health_check.ps1"; Test = { Test-Path $args[0] } }
    )
    
    $passed = 0
    $failed = 0
    
    foreach ($test in $tests) {
        $fullPath = Join-Path $TargetPath $test.Path
        $result = & $test.Test $fullPath
        
        if ($result) {
            Write-RecoveryLog -Step "Validation: $($test.Name)" -Status "success"
            $passed++
        } else {
            Write-RecoveryLog -Step "Validation: $($test.Name)" -Status "error" -Details "Not found: $fullPath"
            $failed++
        }
    }
    
    Write-RecoveryLog -Step "Validation Complete" -Status "info" -Details "Passed: $passed, Failed: $failed"
    
    return ($failed -eq 0)
}

function Save-RecoveryLog {
    $script:RecoveryLog.completed_at = Get-Date -Format "o"
    $script:RecoveryLog.status = if ($script:RecoveryLog.steps | Where-Object { $_.status -eq "error" }) { "failed" } else { "success" }
    
    $logPath = Join-Path $script:RecoveryDir "recovery-log.json"
    $script:RecoveryLog | ConvertTo-Json -Depth 10 | Out-File $logPath
    
    Write-Host "`nRecovery log saved: $logPath" -ForegroundColor Green
}

# Main execution
function Invoke-RecoveryProcedure {
    Write-Host "RawrXD Recovery Procedure" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host "Recovery Type: $RecoveryType" -ForegroundColor Yellow
    Write-Host "Backup: $BackupPath" -ForegroundColor Yellow
    Write-Host "Target: $TargetPath" -ForegroundColor Yellow
    if ($ValidateOnly) { Write-Host "*** VALIDATE ONLY MODE ***" -ForegroundColor Magenta }
    Write-Host ""
    
    try {
        Initialize-RecoveryEnvironment
        
        if (-not $ValidateOnly) {
            Restore-FromBackup
            
            switch ($RecoveryType) {
                "Full" { Invoke-FullRecovery }
                "Partial" { 
                    $components = Read-Host "Enter components to recover (comma-separated)"
                    Invoke-PartialRecovery -Components ($components -split ",")
                }
                "Registry" { Restore-Registries }
                "Config" { Restore-Configuration }
                "PointInTime" { 
                    Write-RecoveryLog -Step "Point-in-Time Recovery" -Status "info" -Details "Target time: $PointInTime"
                    Invoke-FullRecovery
                }
            }
        }
        
        # Validate recovery
        $validation = Test-Recovery
        
        if ($validation) {
            Write-RecoveryLog -Step "Recovery Complete" -Status "success"
        } else {
            Write-RecoveryLog -Step "Recovery Completed with Warnings" -Status "warning"
        }
        
        Save-RecoveryLog
        
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Recovery completed!" -ForegroundColor Green
        Write-Host "Recovery ID: $($script:RecoveryLog.recovery_id)" -ForegroundColor White
        Write-Host "========================================" -ForegroundColor Green
    }
    catch {
        Write-RecoveryLog -Step "Recovery Failed" -Status "error" -Details $_.Exception.Message
        Save-RecoveryLog
        throw
    }
}

# Run recovery
Invoke-RecoveryProcedure
