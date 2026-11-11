# Fast unlinked stub finder - Focus on main source directories
param(
    [string]$ProjectRoot = "d:\RawrXD",
    [string]$CMakeFile = "d:\RawrXD\CMakeLists.txt"
)

Write-Host "Fast Unlinked Stub Scanner" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Read CMakeLists.txt
$cmakeContent = Get-Content $CMakeFile -Raw
$linkedMatches = [regex]::Matches($cmakeContent, '[\w/\\_\-\.]+\.(cpp|c|h|hpp|asm)')
$linkedFiles = $linkedMatches | ForEach-Object { 
    $_.Value -replace '/','\' -replace '^\\','' -replace '\\$',''
} | Where-Object { $_ -ne '' -and $_ -notmatch '^\d+$' } | Sort-Object -Unique

Write-Host "Files linked in CMakeLists.txt: $($linkedFiles.Count)" -ForegroundColor Green

# Key source directories to scan
$sourceDirs = @(
    "$ProjectRoot\src",
    "$ProjectRoot\include",
    "$ProjectRoot\agent",
    "$ProjectRoot\agentic",
    "$ProjectRoot\core",
    "$ProjectRoot\engine",
    "$ProjectRoot\inference",
    "$ProjectRoot\win32app",
    "$ProjectRoot\qtapp",
    "$ProjectRoot\asm",
    "$ProjectRoot\kernels"
)

$allFiles = @()
foreach ($dir in $sourceDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem $dir -File -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.Extension -match '\.(cpp|c|h|hpp|asm)$' }
        $allFiles += $files
    }
}

Write-Host "Source files in key directories: $($allFiles.Count)" -ForegroundColor Green
Write-Host ""

# Normalize for comparison
$linkedNormalized = $linkedFiles | ForEach-Object { 
    ($_ -replace '\\','/' -replace '^/','').ToLower() 
} | Sort-Object -Unique

$unlinked = @()
foreach ($file in $allFiles) {
    $relPath = $file.FullName.Replace($ProjectRoot, "").TrimStart('\', '/').Replace('\', '/').ToLower()
    if ($relPath -notin $linkedNormalized) {
        $unlinked += $file.FullName
    }
}

# Group by directory
$grouped = $unlinked | Group-Object { [System.IO.Path]::GetDirectoryName($_) } | Sort-Object Name

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host "                    UNLINKED STUB FILES                         " -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""
Write-Host "Total Unlinked: $($unlinked.Count)" -ForegroundColor Yellow
Write-Host ""

$totalShown = 0
foreach ($group in $grouped) {
    $dirName = $group.Name.Replace($ProjectRoot, "").TrimStart('\')
    Write-Host "[$dirName]" -ForegroundColor Cyan
    foreach ($file in $group.Group | Sort-Object) {
        $fileName = [System.IO.Path]::GetFileName($file)
        Write-Host "  - $fileName" -ForegroundColor White
        $totalShown++
        if ($totalShown -ge 200) { break }
    }
    if ($totalShown -ge 200) { 
        Write-Host "  ... (truncated, see full report)" -ForegroundColor Gray
        break 
    }
    Write-Host ""
}

# Save full report
$outputFile = "$ProjectRoot\UNLINKED_STUBS_FULL.txt"
"UNLINKED STUB FILES - FULL REPORT" | Out-File $outputFile
"Generated: $(Get-Date)" | Out-File $outputFile -Append
"Total Unlinked: $($unlinked.Count)" | Out-File $outputFile -Append
"" | Out-File $outputFile -Append
$unlinked | Sort-Object | Out-File $outputFile -Append

Write-Host "Full report saved to: $outputFile" -ForegroundColor Green
Write-Host ""
Write-Host "SUMMARY: $($unlinked.Count) unlinked files found" -ForegroundColor $(if($unlinked.Count -gt 100){"Red"}elseif($unlinked.Count -gt 0){"Yellow"}else{"Green"})
