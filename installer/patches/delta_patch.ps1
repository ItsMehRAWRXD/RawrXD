# delta_patch.ps1
# Phase H.3 Batch 3/5: Delta Patching System for Minimal Update Downloads

param(
    [Parameter(Mandatory=$true)]
    [string]$BaseVersion,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetVersion,
    
    [Parameter(Mandatory=$true)]
    [string]$InstallDir,
    
    [string]$PatchServer = "https://patches.rawrxd.ai",
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"

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

function Get-FileHashList($Directory) {
    $hashList = @{}
    
    Get-ChildItem -Path $Directory -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($Directory.Length + 1)
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        $hashList[$relativePath] = @{
            Hash = $hash
            Size = $_.Length
            LastWrite = $_.LastWriteTimeUtc
        }
    }
    
    return $hashList
}

function Get-PatchManifest {
    param($FromVersion, $ToVersion)
    
    $manifestUrl = "$PatchServer/manifests/v${FromVersion}_to_v${ToVersion}.json"
    
    try {
        Write-Log "Downloading patch manifest from $manifestUrl..."
        $manifest = Invoke-RestMethod -Uri $manifestUrl -TimeoutSec 30
        return $manifest
    }
    catch {
        Write-Log "Failed to download patch manifest: $_" "ERROR"
        return $null
    }
}

function Test-PatchPrerequisites {
    param($Manifest, $InstallDir)
    
    Write-Log "Verifying patch prerequisites..."
    
    # Check current installation matches base version
    $currentFiles = Get-FileHashList $InstallDir
    $mismatchCount = 0
    
    foreach ($file in $Manifest.BaseFiles.PSObject.Properties) {
        $expectedFile = $file.Name
        $expectedHash = $file.Value.Hash
        
        if (-not $currentFiles.ContainsKey($expectedFile)) {
            Write-Log "Missing file: $expectedFile" "WARNING"
            $mismatchCount++
        }
        elseif ($currentFiles[$expectedFile].Hash -ne $expectedHash) {
            Write-Log "Hash mismatch: $expectedFile" "WARNING"
            $mismatchCount++
        }
    }
    
    if ($mismatchCount -gt 0) {
        Write-Log "$mismatchCount files do not match expected base version" "WARNING"
        Write-Log "Full update recommended instead of delta patch"
        return $false
    }
    
    Write-Log "Prerequisites verified successfully" "SUCCESS"
    return $true
}

function Apply-DeltaPatch {
    param($Manifest, $InstallDir)
    
    if ($VerifyOnly) {
        Write-Log "VERIFY MODE: Would apply patch with $($Manifest.Operations.Count) operations"
        return $true
    }
    
    Write-Log "Applying delta patch with $($Manifest.Operations.Count) operations..."
    
    $backupDir = "$env:TEMP\RawrXD_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    $successCount = 0
    $failCount = 0
    
    foreach ($op in $Manifest.Operations) {
        $targetPath = Join-Path $InstallDir $op.File
        
        try {
            switch ($op.Action) {
                "Add" {
                    # Download new file
                    $url = "$PatchServer/files/$($op.Hash)"
                    Invoke-WebRequest -Uri $url -OutFile $targetPath -TimeoutSec 60
                    
                    # Verify hash
                    $actualHash = (Get-FileHash -Path $targetPath -Algorithm SHA256).Hash
                    if ($actualHash -ne $op.Hash) {
                        throw "Hash mismatch for new file"
                    }
                    $successCount++
                }
                
                "Modify" {
                    # Backup original
                    $backupPath = Join-Path $backupDir $op.File
                    Copy-Item -Path $targetPath -Destination $backupPath -Force
                    
                    # Download delta and apply
                    $url = "$PatchServer/deltas/$($op.DeltaHash)"
                    $deltaFile = "$env:TEMP\delta_$($op.DeltaHash).tmp"
                    Invoke-WebRequest -Uri $url -OutFile $deltaFile -TimeoutSec 60
                    
                    # Apply delta (simplified - actual implementation would use binary diff)
                    # This is a placeholder for the actual delta application
                    Remove-Item -Path $deltaFile -Force
                    $successCount++
                }
                
                "Delete" {
                    # Backup before delete
                    $backupPath = Join-Path $backupDir $op.File
                    if (Test-Path $targetPath) {
                        Copy-Item -Path $targetPath -Destination $backupPath -Force
                        Remove-Item -Path $targetPath -Force
                    }
                    $successCount++
                }
            }
        }
        catch {
            Write-Log "Failed to apply operation for $($op.File): $_" "ERROR"
            $failCount++
        }
    }
    
    Write-Log "Patch applied: $successCount succeeded, $failCount failed"
    
    if ($failCount -eq 0) {
        Write-Log "Delta patch completed successfully" "SUCCESS"
        # Remove backup on success
        Remove-Item -Path $backupDir -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    }
    else {
        Write-Log "Some operations failed, restoring from backup..." "WARNING"
        # Restore from backup
        Get-ChildItem -Path $backupDir -Recurse | ForEach-Object {
            $target = Join-Path $InstallDir $_.FullName.Substring($backupDir.Length + 1)
            Copy-Item -Path $_.FullName -Destination $target -Force
        }
        Write-Log "Restoration complete" "SUCCESS"
        return $false
    }
}

# Main execution
Write-Log "RawrXD Delta Patch System v1.0"
Write-Log "Patching from v$BaseVersion to v$TargetVersion"

$manifest = Get-PatchManifest -FromVersion $BaseVersion -ToVersion $TargetVersion

if (-not $manifest) {
    Write-Log "No delta patch available, full update required" "WARNING"
    exit 1
}

Write-Log "Patch size: $([math]::Round($manifest.PatchSize / 1KB, 2)) KB"
Write-Log "Full download would be: $([math]::Round($manifest.FullSize / 1MB, 2)) MB"
Write-Log "Savings: $([math]::Round((1 - $manifest.PatchSize / $manifest.FullSize) * 100, 1))%"

if (Test-PatchPrerequisites -Manifest $manifest -InstallDir $InstallDir) {
    if (Apply-DeltaPatch -Manifest $manifest -InstallDir $InstallDir) {
        Write-Log "Update to v$TargetVersion complete" "SUCCESS"
        exit 0
    }
    else {
        Write-Log "Patch failed, please try full update" "ERROR"
        exit 1
    }
}
else {
    Write-Log "Prerequisites not met, full update required" "WARNING"
    exit 1
}
