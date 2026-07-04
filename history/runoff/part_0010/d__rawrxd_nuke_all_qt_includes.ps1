$Script:srcDir = "D:\rawrxd\src"
$Script:files = Get-ChildItem -Path $srcDir -Recurse -Include *.cpp, *.h, *.hpp

# Comprehensive list of ALL Qt includes to remove
$Script:qtIncludesPattern = '(?m)^#include\s+<Q[A-Za-z]+.*?>\s*$'

$Script:totalModified = 0
$Script:totalRemoved = 0

foreach ($file in $files) {
    if (-not (Test-Path $file.FullName)) { continue }
    
$Script:content = Get-Content -Path $file.FullName -Raw
    if (-not $content) { continue }
    
$Script:originalContent = $content
    
    # Remove ALL #include <Q...> lines (but keep <queue>, <quadmath.h> etc by checking for capital letter after Q)
$Script:matches = [regex]::Matches($content, '(?m)^#include\s+<Q[A-Z][a-zA-Z0-9_/]+>\s*$')
    if ($matches.Count -gt 0) {
$Script:content = $content -replace '(?m)^#include\s+<Q[A-Z][a-zA-Z0-9_/]+>\s*$', ''
        $totalRemoved += $matches.Count
    }
    
    if ($content -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $content -Encoding UTF8
        Write-Host "Cleaned: $($file.Name) (removed $($matches.Count) Qt includes)"
        $totalModified++
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total files cleaned: $totalModified" -ForegroundColor Green
Write-Host "Total Qt includes removed: $totalRemoved" -ForegroundColor Green
Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
