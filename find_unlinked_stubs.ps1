# Find all unlinked stub/source files in RawrXD project
param(
    [string]$ProjectRoot = "d:\RawrXD",
    [string]$CMakeFile = "d:\RawrXD\CMakeLists.txt"
)

Write-Host "Scanning for unlinked stub files..." -ForegroundColor Cyan
Write-Host ""

# Read CMakeLists.txt and extract linked files
$cmakeContent = Get-Content $CMakeFile -Raw
$linkedMatches = [regex]::Matches($cmakeContent, '[\w/\\_\-\.]+\.(cpp|c|h|hpp|asm)')
$linkedFiles = $linkedMatches | ForEach-Object { 
    $_.Value -replace '/','\' -replace '^\\','' -replace '\\$',''
} | Where-Object { $_ -ne '' -and $_ -notmatch '^\d+$' } | Sort-Object -Unique

Write-Host "Found $($linkedFiles.Count) files referenced in CMakeLists.txt" -ForegroundColor Green

# Find all source files in project (excluding archive dirs)
$excludePatterns = @(
    "*\.archive\*",
    "*\.archived_orphans*",
    "*\.archived_orphans_ultra*",
    "*\.git\*",
    "*\3rdparty\*",
    "*\history\*",
    "*\_pre_merge_backup\*",
    "*\.ultra_archived\*",
    "*\build\*",
    "*\.vscode\*",
    "*\.github\*"
)

$allSourceFiles = Get-ChildItem $ProjectRoot -Filter "*.cpp" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        $path = $_.FullName
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($path -like $pattern) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -ExpandProperty FullName

$allHeaderFiles = Get-ChildItem $ProjectRoot -Filter "*.h" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        $path = $_.FullName
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($path -like $pattern) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -ExpandProperty FullName

$allHppFiles = Get-ChildItem $ProjectRoot -Filter "*.hpp" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        $path = $_.FullName
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($path -like $pattern) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -ExpandProperty FullName

$allCFiles = Get-ChildItem $ProjectRoot -Filter "*.c" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        $path = $_.FullName
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($path -like $pattern) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -ExpandProperty FullName

$allAsmFiles = Get-ChildItem $ProjectRoot -Filter "*.asm" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { 
        $path = $_.FullName
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($path -like $pattern) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -ExpandProperty FullName

$totalFiles = $allSourceFiles.Count + $allHeaderFiles.Count + $allHppFiles.Count + $allCFiles.Count + $allAsmFiles.Count

Write-Host "Found $totalFiles total source files:" -ForegroundColor Green
Write-Host "  .cpp files: $($allSourceFiles.Count)"
Write-Host "  .h files: $($allHeaderFiles.Count)"
Write-Host "  .hpp files: $($allHppFiles.Count)"
Write-Host "  .c files: $($allCFiles.Count)"
Write-Host "  .asm files: $($allAsmFiles.Count)"
Write-Host ""

# Normalize paths for comparison
function Normalize-Path($path) {
    $relPath = $path.Replace($ProjectRoot, "").TrimStart('\', '/')
    return $relPath -replace '\\','/' -replace '^/',''
}

$linkedNormalized = $linkedFiles | ForEach-Object { $_ -replace '\\','/' -replace '^/','' } | Sort-Object -Unique

# Find unlinked files
$unlinkedCpp = $allSourceFiles | Where-Object { 
    $norm = Normalize-Path $_
    $norm -notin $linkedNormalized
} | Sort-Object

$unlinkedH = $allHeaderFiles | Where-Object { 
    $norm = Normalize-Path $_
    $norm -notin $linkedNormalized
} | Sort-Object

$unlinkedHpp = $allHppFiles | Where-Object { 
    $norm = Normalize-Path $_
    $norm -notin $linkedNormalized
} | Sort-Object

$unlinkedC = $allCFiles | Where-Object { 
    $norm = Normalize-Path $_
    $norm -notin $linkedNormalized
} | Sort-Object

$unlinkedAsm = $allAsmFiles | Where-Object { 
    $norm = Normalize-Path $_
    $norm -notin $linkedNormalized
} | Sort-Object

$totalUnlinked = $unlinkedCpp.Count + $unlinkedH.Count + $unlinkedHpp.Count + $unlinkedC.Count + $unlinkedAsm.Count

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host "                    UNLINKED STUB FILES REPORT                   " -ForegroundColor Red
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
Write-Host ""
Write-Host "Total Unlinked Files: $totalUnlinked" -ForegroundColor Yellow
Write-Host ""

# Group by directory
$groupedCpp = $unlinkedCpp | Group-Object { [System.IO.Path]::GetDirectoryName($_) } | Sort-Object Name
$groupedH = $unlinkedH | Group-Object { [System.IO.Path]::GetDirectoryName($_) } | Sort-Object Name
$groupedHpp = $unlinkedHpp | Group-Object { [System.IO.Path]::GetDirectoryName($_) } | Sort-Object Name

# Output results
if ($unlinkedCpp.Count -gt 0) {
    Write-Host ".CPP FILES (Unlinked: $($unlinkedCpp.Count))" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Gray
    foreach ($group in $groupedCpp) {
        Write-Host ""
        Write-Host "Directory: $($group.Name)" -ForegroundColor Yellow
        foreach ($file in $group.Group | Select-Object -First 20) {
            $filename = [System.IO.Path]::GetFileName($file)
            Write-Host "  - $filename" -ForegroundColor White
        }
        if ($group.Group.Count -gt 20) {
            Write-Host "  ... and $($group.Group.Count - 20) more" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

if ($unlinkedH.Count -gt 0) {
    Write-Host ".H FILES (Unlinked: $($unlinkedH.Count))" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Gray
    foreach ($group in ($groupedH | Select-Object -First 10)) {
        Write-Host ""
        Write-Host "Directory: $($group.Name)" -ForegroundColor Yellow
        foreach ($file in $group.Group | Select-Object -First 10) {
            $filename = [System.IO.Path]::GetFileName($file)
            Write-Host "  - $filename" -ForegroundColor White
        }
        if ($group.Group.Count -gt 10) {
            Write-Host "  ... and $($group.Group.Count - 10) more" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

if ($unlinkedHpp.Count -gt 0) {
    Write-Host ".HPP FILES (Unlinked: $($unlinkedHpp.Count))" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Gray
    foreach ($group in ($groupedHpp | Select-Object -First 10)) {
        Write-Host ""
        Write-Host "Directory: $($group.Name)" -ForegroundColor Yellow
        foreach ($file in $group.Group | Select-Object -First 10) {
            $filename = [System.IO.Path]::GetFileName($file)
            Write-Host "  - $filename" -ForegroundColor White
        }
        if ($group.Group.Count -gt 10) {
            Write-Host "  ... and $($group.Group.Count - 10) more" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

if ($unlinkedC.Count -gt 0) {
    Write-Host ".C FILES (Unlinked: $($unlinkedC.Count))" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Gray
    $unlinkedC | Select-Object -First 30 | ForEach-Object {
        $filename = [System.IO.Path]::GetFileName($_)
        Write-Host "  - $filename" -ForegroundColor White
    }
    if ($unlinkedC.Count -gt 30) {
        Write-Host "  ... and $($unlinkedC.Count - 30) more" -ForegroundColor Gray
    }
    Write-Host ""
}

if ($unlinkedAsm.Count -gt 0) {
    Write-Host ".ASM FILES (Unlinked: $($unlinkedAsm.Count))" -ForegroundColor Cyan
    Write-Host "───────────────────────────────────────────────────────────────" -ForegroundColor Gray
    $unlinkedAsm | Select-Object -First 30 | ForEach-Object {
        $filename = [System.IO.Path]::GetFileName($_)
        Write-Host "  - $filename" -ForegroundColor White
    }
    if ($unlinkedAsm.Count -gt 30) {
        Write-Host "  ... and $($unlinkedAsm.Count - 30) more" -ForegroundColor Gray
    }
    Write-Host ""
}

# Export full list to file
$outputFile = "$ProjectRoot\UNLINKED_STUBS_REPORT.txt"
"UNLINKED STUB FILES REPORT" | Out-File $outputFile
"Generated: $(Get-Date)" | Out-File $outputFile -Append
"Total Unlinked: $totalUnlinked" | Out-File $outputFile -Append
"" | Out-File $outputFile -Append

"=== .CPP FILES ($($unlinkedCpp.Count)) ===" | Out-File $outputFile -Append
$unlinkedCpp | Out-File $outputFile -Append

"" | Out-File $outputFile -Append
"=== .H FILES ($($unlinkedH.Count)) ===" | Out-File $outputFile -Append
$unlinkedH | Out-File $outputFile -Append

"" | Out-File $outputFile -Append
"=== .HPP FILES ($($unlinkedHpp.Count)) ===" | Out-File $outputFile -Append
$unlinkedHpp | Out-File $outputFile -Append

"" | Out-File $outputFile -Append
"=== .C FILES ($($unlinkedC.Count)) ===" | Out-File $outputFile -Append
$unlinkedC | Out-File $outputFile -Append

"" | Out-File $outputFile -Append
"=== .ASM FILES ($($unlinkedAsm.Count)) ===" | Out-File $outputFile -Append
$unlinkedAsm | Out-File $outputFile -Append

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "Full report saved to: $outputFile" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "SUMMARY:" -ForegroundColor Cyan
Write-Host "  Linked in CMakeLists.txt: $($linkedFiles.Count)" -ForegroundColor Green
Write-Host "  Unlinked .cpp files: $($unlinkedCpp.Count)" -ForegroundColor $(if($unlinkedCpp.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "  Unlinked .h files: $($unlinkedH.Count)" -ForegroundColor $(if($unlinkedH.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "  Unlinked .hpp files: $($unlinkedHpp.Count)" -ForegroundColor $(if($unlinkedHpp.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "  Unlinked .c files: $($unlinkedC.Count)" -ForegroundColor $(if($unlinkedC.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "  Unlinked .asm files: $($unlinkedAsm.Count)" -ForegroundColor $(if($unlinkedAsm.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "  TOTAL UNLINKED: $totalUnlinked" -ForegroundColor $(if($totalUnlinked -gt 0){"Red"}else{"Green"})
