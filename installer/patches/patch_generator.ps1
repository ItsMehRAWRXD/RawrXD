# patch_generator.ps1
# Phase H.3 Batch 3/5: Delta Patch Generator for Release Management

param(
    [Parameter(Mandatory=$true)]
    [string]$OldVersionDir,
    
    [Parameter(Mandatory=$true)]
    [string]$NewVersionDir,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputDir,
    
    [string]$OldVersion = "1.0.0",
    [string]$NewVersion = "1.0.1"
)

$ErrorActionPreference = "Stop"

function Get-FileHashList($Directory) {
    $hashList = @{}
    
    Get-ChildItem -Path $Directory -Recurse -File | ForEach-Object {
        $relativePath = $_.FullName.Substring($Directory.Length + 1)
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        $hashList[$relativePath] = @{
            Hash = $hash
            Size = $_.Length
            FullPath = $_.FullName
        }
    }
    
    return $hashList
}

function Write-Log($Message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

# Main execution
Write-Log "RawrXD Patch Generator v1.0"
Write-Log "Comparing v$OldVersion to v$NewVersion"

# Get file lists
Write-Log "Scanning old version..."
$oldFiles = Get-FileHashList $OldVersionDir

Write-Log "Scanning new version..."
$newFiles = Get-FileHashList $NewVersionDir

# Calculate differences
$operations = @()
$patchSize = 0

# Find added and modified files
foreach ($file in $newFiles.Keys) {
    if (-not $oldFiles.ContainsKey($file)) {
        # New file
        $operations += @{
            Action = "Add"
            File = $file
            Hash = $newFiles[$file].Hash
            Size = $newFiles[$file].Size
        }
        $patchSize += $newFiles[$file].Size
        Write-Log "ADD: $file ($([math]::Round($newFiles[$file].Size / 1KB, 2)) KB)"
    }
    elseif ($oldFiles[$file].Hash -ne $newFiles[$file].Hash) {
        # Modified file
        $operations += @{
            Action = "Modify"
            File = $file
            OldHash = $oldFiles[$file].Hash
            NewHash = $newFiles[$file].Hash
            OldSize = $oldFiles[$file].Size
            NewSize = $newFiles[$file].Size
        }
        $patchSize += $newFiles[$file].Size  # Simplified - actual delta would be smaller
        Write-Log "MODIFY: $file ($([math]::Round($newFiles[$file].Size / 1KB, 2)) KB)"
    }
}

# Find deleted files
foreach ($file in $oldFiles.Keys) {
    if (-not $newFiles.ContainsKey($file)) {
        $operations += @{
            Action = "Delete"
            File = $file
            Hash = $oldFiles[$file].Hash
        }
        Write-Log "DELETE: $file"
    }
}

# Calculate statistics
$oldTotalSize = ($oldFiles.Values | Measure-Object -Property Size -Sum).Sum
$newTotalSize = ($newFiles.Values | Measure-Object -Property Size -Sum).Sum

# Create manifest
$manifest = @{
    Metadata = @{
        OldVersion = $OldVersion
        NewVersion = $NewVersion
        GeneratedAt = Get-Date -Format "o"
        GeneratorVersion = "1.0.0"
    }
    Statistics = @{
        OldFileCount = $oldFiles.Count
        NewFileCount = $newFiles.Count
        OldTotalSize = $oldTotalSize
        NewTotalSize = $newTotalSize
        PatchSize = $patchSize
        FullSize = $newTotalSize
        SavingsPercent = [math]::Round((1 - $patchSize / $newTotalSize) * 100, 2)
    }
    BaseFiles = $oldFiles
    Operations = $operations
}

# Create output directory
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Save manifest
$manifestPath = Join-Path $OutputDir "v${OldVersion}_to_v${NewVersion}.json"
$manifest | ConvertTo-Json -Depth 10 | Out-File $manifestPath -Encoding UTF8

Write-Log ""
Write-Log "Patch manifest generated: $manifestPath"
Write-Log ""
Write-Log "Statistics:"
Write-Log "  Old version: $($oldFiles.Count) files, $([math]::Round($oldTotalSize / 1MB, 2)) MB"
Write-Log "  New version: $($newFiles.Count) files, $([math]::Round($newTotalSize / 1MB, 2)) MB"
Write-Log "  Operations: $($operations.Count)"
Write-Log "  Patch size: $([math]::Round($patchSize / 1MB, 2)) MB"
Write-Log "  Savings: $([math]::Round((1 - $patchSize / $newTotalSize) * 100, 1))%"
