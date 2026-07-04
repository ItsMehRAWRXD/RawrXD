$Script:ErrorActionPreference = "SilentlyContinue"

function Copy-ChangedFiles {
    param(
        [string]$RepoRoot,
        [string]$DestRoot,
        [string]$Label
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Label" -ForegroundColor Cyan
    Write-Host "  Source: $RepoRoot" -ForegroundColor Gray
    Write-Host "  Dest:   $DestRoot" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    
    Push-Location $RepoRoot
    
    # Get modified files
$Script:modified = git diff --name-only HEAD 2>$null
$Script:untracked = git ls-files --others --exclude-standard 2>$null
    
$Script:allFiles = @()
    if ($modified) { $allFiles += $modified }
    if ($untracked) { $allFiles += $untracked }
$Script:allFiles = $allFiles | Sort-Object -Unique
    
    Write-Host "  Total changed files: $($allFiles.Count)" -ForegroundColor Yellow
    
$Script:copied = 0
$Script:skipped = 0
$Script:errors = 0
    
    foreach ($f in $allFiles) {
$Script:src = Join-Path $RepoRoot $f
$Script:dest = Join-Path $DestRoot $f
        
        if (Test-Path $src -PathType Leaf) {
$Script:destDir = Split-Path $dest -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            try {
                Copy-Item $src $dest -Force -ErrorAction Stop
                $copied++
            } catch {
                $errors++
            }
        } else {
            $skipped++
        }
        
        if ($copied % 1000 -eq 0 -and $copied -gt 0) {
            Write-Host "    ...copied $copied files" -ForegroundColor Gray
        }
    }
    
    Pop-Location
    
    Write-Host "  ✅ Copied: $copied | Skipped (missing): $skipped | Errors: $errors" -ForegroundColor Green
    return $copied
}

# Also save file lists for the D:\ drive-level repo (non-rawrxd files)
function Copy-DriveLevel {
    param(
        [string]$DestRoot
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  D:\ Drive-Level Repo (non-rawrxd)" -ForegroundColor Cyan
    Write-Host "  Dest: $DestRoot" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    
    Push-Location "D:\"
    
$Script:modified = git diff --name-only HEAD 2>$null | Where-Object { -not $_.StartsWith("rawrxd/") }
$Script:untracked = git ls-files --others --exclude-standard 2>$null | Where-Object { -not $_.StartsWith("rawrxd/") }
    
$Script:allFiles = @()
    if ($modified) { $allFiles += $modified }
    if ($untracked) { $allFiles += $untracked }
$Script:allFiles = $allFiles | Sort-Object -Unique
    
    Write-Host "  Total changed files: $($allFiles.Count)" -ForegroundColor Yellow
    
$Script:copied = 0
$Script:skipped = 0
$Script:errors = 0
    
    foreach ($f in $allFiles) {
$Script:src = Join-Path "D:\" $f
$Script:dest = Join-Path $DestRoot $f
        
        if (Test-Path $src -PathType Leaf) {
$Script:destDir = Split-Path $dest -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            try {
                Copy-Item $src $dest -Force -ErrorAction Stop
                $copied++
            } catch {
                $errors++
            }
        } else {
            $skipped++
        }
        
        if ($copied % 1000 -eq 0 -and $copied -gt 0) {
            Write-Host "    ...copied $copied files" -ForegroundColor Gray
        }
    }
    
    Pop-Location
    
    Write-Host "  ✅ Copied: $copied | Skipped (missing): $skipped | Errors: $errors" -ForegroundColor Green
    return $copied
}

$Script:stash = "D:\Stash House"

Write-Host "==========================================" -ForegroundColor Magenta
Write-Host "  STASH HOUSE - Full File Backup" -ForegroundColor Magenta
Write-Host "  Target: $stash" -ForegroundColor Magenta
Write-Host "==========================================" -ForegroundColor Magenta

$Script:totalCopied = 0

# 1. D:\rawrxd repo
$totalCopied += Copy-ChangedFiles -RepoRoot "D:\rawrxd" -DestRoot "$stash\RawrXD-Main" -Label "RawrXD Main Repo"

# 2. D:\ drive-level repo (everything NOT in rawrxd/)
$totalCopied += Copy-DriveLevel -DestRoot "$stash\Drive-Level"

Write-Host "`n==========================================" -ForegroundColor Magenta
Write-Host "  STASH COMPLETE" -ForegroundColor Magenta
Write-Host "  Total files copied: $totalCopied" -ForegroundColor Green
Write-Host "  Location: $stash" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Magenta

# Save manifest
$Script:manifest = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalFilesCopied = $totalCopied
    Location = $stash
}
$manifest | ConvertTo-Json | Out-File "$stash\_MANIFEST.json" -Encoding utf8 -Force
Write-Host "`nManifest saved to $stash\_MANIFEST.json"
