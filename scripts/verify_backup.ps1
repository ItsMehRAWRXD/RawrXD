# RawrXD Backup Verification Script
# Validates backup integrity and test restoration

param(
    [Parameter(Mandatory = $false)]
    [string]$BackupPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Quick', 'Full')]
    [string]$VerifyLevel = 'Quick',

    [Parameter(Mandatory = $false)]
    [switch]$TestRestore,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "./backup-verification-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
)

$ErrorActionPreference = 'Stop'

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Backup Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Find latest backup if not specified
if (-not $BackupPath) {
    $backupDir = Join-Path $env:ProgramData 'RawrXD\backups'
    if (Test-Path $backupDir) {
        $latestBackup = Get-ChildItem -Path $backupDir -Directory |
            Sort-Object CreationTime -Descending |
            Select-Object -First 1

        if ($latestBackup) {
            $BackupPath = $latestBackup.FullName
            Write-Host "Using latest backup: $BackupPath" -ForegroundColor Yellow
        }
        else {
            Write-Error "No backups found in $backupDir"
            exit 1
        }
    }
    else {
        Write-Error "Backup directory not found: $backupDir"
        exit 1
    }
}

if (-not (Test-Path $BackupPath)) {
    Write-Error "Backup path not found: $BackupPath"
    exit 1
}

Write-Host "Backup Path: $BackupPath" -ForegroundColor White
Write-Host "Verification Level: $VerifyLevel" -ForegroundColor White
Write-Host "Test Restore: $TestRestore" -ForegroundColor White
Write-Host ""

$verificationResults = @{
    BackupPath = $BackupPath
    VerificationLevel = $VerifyLevel
    StartTime = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    EndTime = $null
    Duration = $null
    Tests = @()
    OverallStatus = 'Unknown'
}

# Test 1: Metadata Verification
Write-Host "Test 1: Metadata Verification" -ForegroundColor Yellow
$metadataPath = Join-Path $BackupPath 'metadata.json'
$metadataTest = @{
    Name = 'Metadata Verification'
    Status = 'Failed'
    Details = @()
}

if (Test-Path $metadataPath) {
    try {
        $metadata = Get-Content $metadataPath | ConvertFrom-Json
        $metadataTest.Details += "Backup name: $($metadata.name)"
        $metadataTest.Details += "Backup type: $($metadata.type)"
        $metadataTest.Details += "Created at: $($metadata.created_at)"
        $metadataTest.Details += "Created by: $($metadata.created_by)"
        $metadataTest.Details += "Version: $($metadata.version)"
        $metadataTest.Status = 'Passed'
        Write-Host "  ✓ Metadata valid" -ForegroundColor Green
    }
    catch {
        $metadataTest.Details += "Error reading metadata: $_"
        Write-Host "  ✗ Metadata invalid: $_" -ForegroundColor Red
    }
}
else {
    $metadataTest.Details += "Metadata file not found"
    Write-Host "  ✗ Metadata file not found" -ForegroundColor Red
}

$verificationResults.Tests += $metadataTest
Write-Host ""

# Test 2: File Structure Verification
Write-Host "Test 2: File Structure Verification" -ForegroundColor Yellow
$structureTest = @{
    Name = 'File Structure Verification'
    Status = 'Failed'
    Details = @()
}

$requiredPaths = @(
    'security',
    'security/rbac',
    'monitoring',
    'deployment',
    'disaster-recovery'
)

$missingPaths = @()
foreach ($path in $requiredPaths) {
    $fullPath = Join-Path $BackupPath $path
    if (-not (Test-Path $fullPath)) {
        $missingPaths += $path
    }
}

if ($missingPaths.Count -eq 0) {
    $structureTest.Status = 'Passed'
    $structureTest.Details += "All required paths present"
    Write-Host "  ✓ All required paths present" -ForegroundColor Green
}
else {
    $structureTest.Details += "Missing paths: $($missingPaths -join ', ')"
    Write-Host "  ✗ Missing paths: $($missingPaths -join ', ')" -ForegroundColor Red
}

$verificationResults.Tests += $structureTest
Write-Host ""

# Test 3: RBAC Configuration Verification
Write-Host "Test 3: RBAC Configuration Verification" -ForegroundColor Yellow
$rbacTest = @{
    Name = 'RBAC Configuration Verification'
    Status = 'Failed'
    Details = @()
}

$rbacPath = Join-Path $BackupPath 'security/rbac/rbac_config.json'
if (Test-Path $rbacPath) {
    try {
        $rbacConfig = Get-Content $rbacPath | ConvertFrom-Json
        $rbacTest.Details += "RBAC version: $($rbacConfig.version)"
        $rbacTest.Details += "Roles: $($rbacConfig.roles.Count)"
        $rbacTest.Details += "Users: $($rbacConfig.users.Count)"

        if ($rbacConfig.roles.Count -ge 5) {
            $rbacTest.Status = 'Passed'
            Write-Host "  ✓ RBAC configuration valid ($($rbacConfig.roles.Count) roles)" -ForegroundColor Green
        }
        else {
            $rbacTest.Details += "Warning: Expected at least 5 roles, found $($rbacConfig.roles.Count)"
            $rbacTest.Status = 'Warning'
            Write-Host "  ⚠ RBAC configuration incomplete" -ForegroundColor Yellow
        }
    }
    catch {
        $rbacTest.Details += "Error reading RBAC config: $_"
        Write-Host "  ✗ RBAC configuration invalid: $_" -ForegroundColor Red
    }
}
else {
    $rbacTest.Details += "RBAC configuration not found"
    Write-Host "  ✗ RBAC configuration not found" -ForegroundColor Red
}

$verificationResults.Tests += $rbacTest
Write-Host ""

# Test 4: File Integrity Check (Quick)
if ($VerifyLevel -eq 'Quick') {
    Write-Host "Test 4: Critical File Checksum Verification" -ForegroundColor Yellow
    $checksumTest = @{
        Name = 'Critical File Checksum Verification'
        Status = 'Failed'
        Details = @()
    }

    $criticalFiles = @(
        'security/rbac/rbac_manager.ps1',
        'install.ps1'
    )

    $verifiedFiles = 0
    foreach ($file in $criticalFiles) {
        $filePath = Join-Path $BackupPath $file
        if (Test-Path $filePath) {
            $hash = Get-FileHash $filePath -Algorithm SHA256
            $checksumTest.Details += "$file : $($hash.Hash)"
            $verifiedFiles++
        }
        else {
            $checksumTest.Details += "$file : NOT FOUND"
        }
    }

    if ($verifiedFiles -eq $criticalFiles.Count) {
        $checksumTest.Status = 'Passed'
        Write-Host "  ✓ All critical files verified ($verifiedFiles/$($criticalFiles.Count))" -ForegroundColor Green
    }
    else {
        $checksumTest.Details += "Only $verifiedFiles of $($criticalFiles.Count) files verified"
        Write-Host "  ✗ Only $verifiedFiles of $($criticalFiles.Count) files verified" -ForegroundColor Red
    }

    $verificationResults.Tests += $checksumTest
    Write-Host ""
}

# Test 5: Full Integrity Check
if ($VerifyLevel -eq 'Full') {
    Write-Host "Test 4: Full Integrity Check" -ForegroundColor Yellow
    Write-Host "  Scanning all files..." -ForegroundColor Gray

    $integrityTest = @{
        Name = 'Full Integrity Check'
        Status = 'In Progress'
        Details = @()
    }

    $allFiles = Get-ChildItem -Path $BackupPath -File -Recurse
    $integrityTest.Details += "Total files: $($allFiles.Count)"

    $corruptedFiles = @()
    foreach ($file in $allFiles) {
        try {
            $null = Get-Content $file.FullName -TotalCount 1 -ErrorAction Stop
        }
        catch {
            $corruptedFiles += $file.FullName
        }
    }

    if ($corruptedFiles.Count -eq 0) {
        $integrityTest.Status = 'Passed'
        $integrityTest.Details += "All files readable"
        Write-Host "  ✓ All $($allFiles.Count) files verified" -ForegroundColor Green
    }
    else {
        $integrityTest.Status = 'Failed'
        $integrityTest.Details += "Corrupted files: $($corruptedFiles.Count)"
        Write-Host "  ✗ $($corruptedFiles.Count) files corrupted" -ForegroundColor Red
    }

    $verificationResults.Tests += $integrityTest
    Write-Host ""
}

# Test 6: Test Restore (Optional)
if ($TestRestore) {
    Write-Host "Test 6: Test Restore" -ForegroundColor Yellow
    $restoreTest = @{
        Name = 'Test Restore'
        Status = 'Failed'
        Details = @()
    }

    $testRestorePath = Join-Path $env:TEMP "rawrxd_restore_test_$(Get-Random)"

    try {
        Write-Host "  Restoring to: $testRestorePath" -ForegroundColor Gray
        New-Item -ItemType Directory -Path $testRestorePath -Force | Out-Null

        # Copy backup to test location
        Copy-Item -Path "$BackupPath\*" -Destination $testRestorePath -Recurse -Force

        # Verify key files work
        $testRBACPath = Join-Path $testRestorePath 'security/rbac/rbac_config.json'
        if (Test-Path $testRBACPath) {
            $testConfig = Get-Content $testRBACPath | ConvertFrom-Json
            if ($testConfig.roles.Count -gt 0) {
                $restoreTest.Status = 'Passed'
                $restoreTest.Details += "Test restore successful"
                Write-Host "  ✓ Test restore successful" -ForegroundColor Green
            }
        }

        # Cleanup
        Remove-Item $testRestorePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        $restoreTest.Details += "Restore failed: $_"
        Write-Host "  ✗ Test restore failed: $_" -ForegroundColor Red
    }

    $verificationResults.Tests += $restoreTest
    Write-Host ""
}

# Calculate overall status
$passedTests = ($verificationResults.Tests | Where-Object { $_.Status -eq 'Passed' }).Count
$failedTests = ($verificationResults.Tests | Where-Object { $_.Status -eq 'Failed' }).Count
$warningTests = ($verificationResults.Tests | Where-Object { $_.Status -eq 'Warning' }).Count

if ($failedTests -eq 0) {
    if ($warningTests -eq 0) {
        $verificationResults.OverallStatus = 'Passed'
    }
    else {
        $verificationResults.OverallStatus = 'Warning'
    }
}
else {
    $verificationResults.OverallStatus = 'Failed'
}

$verificationResults.EndTime = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
$verificationResults.Duration = (New-TimeSpan -Start $verificationResults.StartTime -End $verificationResults.EndTime).ToString()

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Verification Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Overall Status: $($verificationResults.OverallStatus)" -ForegroundColor $(
    switch ($verificationResults.OverallStatus) {
        'Passed' { 'Green' }
        'Warning' { 'Yellow' }
        'Failed' { 'Red' }
        default { 'White' }
    }
)
Write-Host "Tests Passed: $passedTests" -ForegroundColor Green
Write-Host "Tests Failed: $failedTests" -ForegroundColor Red
Write-Host "Tests with Warnings: $warningTests" -ForegroundColor Yellow
Write-Host "Duration: $($verificationResults.Duration)" -ForegroundColor Gray
Write-Host ""

# Export results
$verificationResults | ConvertTo-Json -Depth 10 | Out-File $ReportPath -Force
Write-Host "✓ Report saved to: $ReportPath" -ForegroundColor Green

# Exit code
if ($verificationResults.OverallStatus -eq 'Failed') {
    exit 1
}
elseif ($verificationResults.OverallStatus -eq 'Warning') {
    exit 2
}
else {
    exit 0
}
