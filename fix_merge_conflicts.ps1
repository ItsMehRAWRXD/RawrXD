# ============================================================================
# fix_merge_conflicts.ps1 — Strip all merge conflict markers from source files
# Keeps the HEAD (our) side of each conflict, discards the incoming side.
# ============================================================================

$srcRoot = "D:\RawrXD\src"
$extensions = @("*.cpp", "*.h", "*.hpp", "*.c", "*.asm", "*.inc")

# Find all files with conflict markers
$affectedFiles = @()
foreach ($ext in $extensions) {
    $files = Get-ChildItem -Path $srcRoot -Recurse -Filter $ext
    foreach ($f in $files) {
        $content = Get-Content -Path $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '<<<<<<<|=======|>>>>>>>') {
            $affectedFiles += $f.FullName
        }
    }
}

Write-Host "Found $($affectedFiles.Count) files with merge conflict markers"
$fixedCount = 0
$errorCount = 0

foreach ($file in $affectedFiles) {
    try {
        $lines = Get-Content -Path $file
        $newLines = @()
        $inConflict = $false
        $inOurs = $false
        $inTheirs = $false
        
        foreach ($line in $lines) {
            if ($line -match '^<<<<<<<') {
                $inConflict = $true
                $inOurs = $true
                $inTheirs = $false
                continue
            }
            elseif ($line -match '^=======$') {
                if ($inConflict) {
                    $inOurs = $false
                    $inTheirs = $true
                }
                continue
            }
            elseif ($line -match '^>>>>>>>') {
                $inConflict = $false
                $inOurs = $false
                $inTheirs = $false
                continue
            }
            
            if (-not $inConflict -or $inOurs) {
                $newLines += $line
            }
        }
        
        Set-Content -Path $file -Value $newLines -Force
        $fixedCount++
        Write-Host "  ✓ Fixed: $($file -replace [regex]::Escape($srcRoot), '')"
    }
    catch {
        Write-Host "  ✗ Error: $($file -replace [regex]::Escape($srcRoot), '') - $_"
        $errorCount++
    }
}

Write-Host ""
Write-Host "=== Merge Conflict Fix Complete ==="
Write-Host "Files fixed: $fixedCount"
Write-Host "Errors: $errorCount"
Write-Host "=================================="
