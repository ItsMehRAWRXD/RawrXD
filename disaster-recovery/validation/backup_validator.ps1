# RawrXD Backup Validator
# Automated validation of backup integrity and recoverability

param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath,
    
    [string]$EncryptionKey,
    [switch]$TestRestore,
    [string]$TestRestorePath = "disaster-recovery/validation/test-restore",
    [switch]$GenerateReport,
    [string]$ReportPath = "disaster-recovery/validation/reports"
)

$ErrorActionPreference = "Stop"

# Validation results
$script:ValidationResults = @{
    validation_id = [Guid]::NewGuid().ToString()
    timestamp = Get-Date -Format "o"
    backup_path = $BackupPath
    tests = @()
    overall_status = "pending"
}

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Status,  # pass, fail, warning
        [string]$Details = "",
        [hashtable]$Metrics = @{}
    )
    
    $script:ValidationResults.tests += @{
        name = $TestName
        status = $Status
        timestamp = Get-Date -Format "o"
        details = $Details
        metrics = $Metrics
    }
    
    $color = switch ($Status) {
        "pass" { "Green" }
        "fail" { "Red" }
        "warning" { "Yellow" }
        default { "White" }
    }
    
    $icon = switch ($Status) {
        "pass" { "✓" }
        "fail" { "✗" }
        "warning" { "⚠" }
        default { "?" }
    }
    
    Write-Host "$icon $TestName`: $Status" -ForegroundColor $color
    if ($Details) {
        Write-Host "  $Details" -ForegroundColor Gray
    }
}

function Test-BackupExists {
    Write-Host "`nTest: Backup File Exists" -ForegroundColor Cyan
    
    if (Test-Path $BackupPath) {
        $fileInfo = Get-Item $BackupPath
        Add-TestResult -TestName "Backup File Exists" -Status "pass" -Details "Size: $([math]::Round($fileInfo.Length/1MB, 2)) MB" -Metrics @{
            size_bytes = $fileInfo.Length
            created = $fileInfo.CreationTime.ToString("o")
        }
        return $true
    } else {
        Add-TestResult -TestName "Backup File Exists" -Status "fail" -Details "File not found: $BackupPath"
        return $false
    }
}

function Test-BackupMetadata {
    Write-Host "`nTest: Backup Metadata" -ForegroundColor Cyan
    
    $metadataPath = "$BackupPath.json"
    
    if (-not (Test-Path $metadataPath)) {
        Add-TestResult -TestName "Backup Metadata" -Status "warning" -Details "Metadata file not found"
        return
    }
    
    try {
        $metadata = Get-Content $metadataPath | ConvertFrom-Json
        
        $requiredFields = @("backup_id", "timestamp", "type", "checksum")
        $missingFields = @()
        
        foreach ($field in $requiredFields) {
            if (-not $metadata.$field) {
                $missingFields += $field
            }
        }
        
        if ($missingFields.Count -eq 0) {
            Add-TestResult -TestName "Backup Metadata" -Status "pass" -Details "All required fields present" -Metrics @{
                backup_id = $metadata.backup_id
                backup_type = $metadata.type
                created = $metadata.timestamp
            }
        } else {
            Add-TestResult -TestName "Backup Metadata" -Status "warning" -Details "Missing fields: $($missingFields -join ', ')"
        }
    }
    catch {
        Add-TestResult -TestName "Backup Metadata" -Status "fail" -Details "Failed to parse metadata: $_"
    }
}

function Test-BackupChecksum {
    Write-Host "`nTest: Backup Checksum" -ForegroundColor Cyan
    
    $metadataPath = "$BackupPath.json"
    if (-not (Test-Path $metadataPath)) {
        Add-TestResult -TestName "Backup Checksum" -Status "warning" -Details "Cannot verify - metadata not found"
        return
    }
    
    try {
        $metadata = Get-Content $metadataPath | ConvertFrom-Json
        $expectedChecksum = $metadata.checksum
        
        if (-not $expectedChecksum) {
            Add-TestResult -TestName "Backup Checksum" -Status "warning" -Details "No checksum in metadata"
            return
        }
        
        $actualChecksum = (Get-FileHash $BackupPath -Algorithm SHA256).Hash
        
        if ($actualChecksum -eq $expectedChecksum) {
            Add-TestResult -TestName "Backup Checksum" -Status "pass" -Details "Checksums match" -Metrics @{
                checksum = $actualChecksum
            }
        } else {
            Add-TestResult -TestName "Backup Checksum" -Status "fail" -Details "Checksum mismatch! Expected: $expectedChecksum, Actual: $actualChecksum"
        }
    }
    catch {
        Add-TestResult -TestName "Backup Checksum" -Status "fail" -Details "Failed to verify checksum: $_"
    }
}

function Test-BackupIntegrity {
    Write-Host "`nTest: Backup Integrity" -ForegroundColor Cyan
    
    $isEncrypted = $BackupPath.EndsWith(".encrypted")
    $archivePath = $BackupPath
    
    # Decrypt if needed
    if ($isEncrypted) {
        if (-not $EncryptionKey) {
            Add-TestResult -TestName "Backup Integrity" -Status "warning" -Details "Cannot test - encrypted backup without key"
            return
        }
        
        try {
            $encryptedBytes = [System.IO.File]::ReadAllBytes($BackupPath)
            $iv = $encryptedBytes[0..15]
            $cipherText = $encryptedBytes[16..($encryptedBytes.Length - 1)]
            
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptionKey.PadRight(32))
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $keyBytes
            $aes.IV = $iv
            
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
            
            $archivePath = "$env:TEMP\backup-test-$(Get-Random).zip"
            [System.IO.File]::WriteAllBytes($archivePath, $decryptedBytes)
            
            Add-TestResult -TestName "Backup Decryption" -Status "pass" -Details "Successfully decrypted backup"
        }
        catch {
            Add-TestResult -TestName "Backup Decryption" -Status "fail" -Details "Failed to decrypt: $_"
            return
        }
    }
    
    # Test archive integrity
    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
        $entries = $archive.Entries
        $entryCount = $entries.Count
        
        # Try to read a few entries
        $readableEntries = 0
        $corruptEntries = 0
        
        foreach ($entry in $entries | Select-Object -First 10) {
            try {
                $stream = $entry.Open()
                $stream.Close()
                $readableEntries++
            }
            catch {
                $corruptEntries++
            }
        }
        
        $archive.Dispose()
        
        if ($corruptEntries -eq 0) {
            Add-TestResult -TestName "Backup Integrity" -Status "pass" -Details "Archive is valid" -Metrics @{
                total_entries = $entryCount
                tested_entries = $readableEntries
            }
        } else {
            Add-TestResult -TestName "Backup Integrity" -Status "fail" -Details "Found $corruptEntries corrupt entries"
        }
    }
    catch {
        Add-TestResult -TestName "Backup Integrity" -Status "fail" -Details "Failed to open archive: $_"
    }
    finally {
        if ($archivePath -ne $BackupPath -and (Test-Path $archivePath)) {
            Remove-Item $archivePath -Force
        }
    }
}

function Test-BackupRestore {
    Write-Host "`nTest: Backup Restore" -ForegroundColor Cyan
    
    if (-not $TestRestore) {
        Add-TestResult -TestName "Backup Restore" -Status "warning" -Details "Skipped - TestRestore not specified"
        return
    }
    
    # Clean up test directory
    if (Test-Path $TestRestorePath) {
        Remove-Item $TestRestorePath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $TestRestorePath -Force | Out-Null
    
    try {
        # Simulate restore
        $archivePath = $BackupPath
        $isEncrypted = $BackupPath.EndsWith(".encrypted")
        
        if ($isEncrypted) {
            # Decrypt first
            $encryptedBytes = [System.IO.File]::ReadAllBytes($BackupPath)
            $iv = $encryptedBytes[0..15]
            $cipherText = $encryptedBytes[16..($encryptedBytes.Length - 1)]
            
            $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($EncryptionKey.PadRight(32))
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $keyBytes
            $aes.IV = $iv
            
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
            
            $archivePath = "$env:TEMP\restore-test-$(Get-Random).zip"
            [System.IO.File]::WriteAllBytes($archivePath, $decryptedBytes)
        }
        
        # Extract
        Expand-Archive -Path $archivePath -DestinationPath $TestRestorePath -Force
        
        # Verify key files exist
        $criticalFiles = @(
            "security/integration/secure_hotpatch.ps1",
            "security/phase_h_enterprise_security/rbac/rbac_manager.ps1",
            "security/phase_g1_hotpatch/registry/patch_registry.json"
        )
        
        $foundFiles = 0
        foreach ($file in $criticalFiles) {
            $fullPath = Join-Path $TestRestorePath $file
            if (Test-Path $fullPath) {
                $foundFiles++
            }
        }
        
        if ($foundFiles -eq $criticalFiles.Count) {
            Add-TestResult -TestName "Backup Restore" -Status "pass" -Details "All critical files restored successfully" -Metrics @{
                critical_files_found = $foundFiles
                total_critical_files = $criticalFiles.Count
            }
        } else {
            Add-TestResult -TestName "Backup Restore" -Status "warning" -Details "Only $foundFiles/$($criticalFiles.Count) critical files found"
        }
    }
    catch {
        Add-TestResult -TestName "Backup Restore" -Status "fail" -Details "Restore failed: $_"
    }
    finally {
        # Cleanup
        if (Test-Path $TestRestorePath) {
            Remove-Item $TestRestorePath -Recurse -Force
        }
        if ($archivePath -ne $BackupPath -and (Test-Path $archivePath)) {
            Remove-Item $archivePath -Force
        }
    }
}

function Get-ValidationSummary {
    $passed = ($script:ValidationResults.tests | Where-Object { $_.status -eq "pass" }).Count
    $failed = ($script:ValidationResults.tests | Where-Object { $_.status -eq "fail" }).Count
    $warnings = ($script:ValidationResults.tests | Where-Object { $_.status -eq "warning" }).Count
    
    $script:ValidationResults.overall_status = if ($failed -gt 0) { "fail" } elseif ($warnings -gt 0) { "warning" } else { "pass" }
    
    return @{
        passed = $passed
        failed = $failed
        warnings = $warnings
        total = $script:ValidationResults.tests.Count
        status = $script:ValidationResults.overall_status
    }
}

function Save-ValidationReport {
    if (-not (Test-Path $ReportPath)) {
        New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportFile = Join-Path $ReportPath "validation-report-$timestamp.json"
    
    $script:ValidationResults | ConvertTo-Json -Depth 10 | Out-File $reportFile
    
    Write-Host "`nValidation report saved: $reportFile" -ForegroundColor Green
}

# Main execution
function Invoke-BackupValidator {
    Write-Host "RawrXD Backup Validator" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host "Backup: $BackupPath" -ForegroundColor Yellow
    Write-Host ""
    
    # Run tests
    $backupExists = Test-BackupExists
    
    if ($backupExists) {
        Test-BackupMetadata
        Test-BackupChecksum
        Test-BackupIntegrity
        Test-BackupRestore
    }
    
    # Summary
    $summary = Get-ValidationSummary
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Validation Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Passed:   $($summary.passed)" -ForegroundColor Green
    Write-Host "Failed:   $($summary.failed)" -ForegroundColor Red
    Write-Host "Warnings: $($summary.warnings)" -ForegroundColor Yellow
    Write-Host "Total:    $($summary.total)" -ForegroundColor White
    Write-Host "Status:   $($summary.status.ToUpper())" -ForegroundColor $(if($summary.status -eq "pass"){"Green"}elseif($summary.status -eq "warning"){"Yellow"}else{"Red"})
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Save report
    if ($GenerateReport) {
        Save-ValidationReport
    }
    
    # Exit code
    if ($summary.failed -gt 0) { exit 1 }
    if ($summary.warnings -gt 0) { exit 2 }
    exit 0
}

# Run validator
Invoke-BackupValidator
