$cmakeFile = 'F:\~dev\rawrxd\CMakeLists.txt'
$content = Get-Content $cmakeFile -Raw
$pattern = '(?<=(?:^|\n)\s*)(add_(?:executable|library)\s*\((\w+)[^\)]*?(?:\r?\n)\s*\))'
$matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
Write-Host "Found $($matches.Count) add_executable/library calls"
$wrapCount = 0
foreach ($m in $matches) {
    $fullBlock = $m.Groups[0].Value
    $targetName = $m.Groups[2].Value
    $sourceMatches = [regex]::Matches($fullBlock, '(src/[^\s\)]+|tests/[^\s\)]+|B014/[^\s\)]+|[^\s\)/]+\.cpp|[^\s\)/]+\.c|[^\s\)/]+\.asm)')
    $missingFiles = @()
    foreach ($sm in $sourceMatches) {
        $path = $sm.Value
        $fullPath = Join-Path 'F:\~dev\rawrxd' ($path -replace '/','\')
        if (-not (Test-Path $fullPath -PathType Leaf)) {
            $missingFiles += $path
        }
    }
    if ($missingFiles.Count -gt 0) {
        Write-Host "BROKEN: $targetName  Missing: $($missingFiles -join ', ')"
        $wrapCount++
    }
}
Write-Host "Total broken targets: $wrapCount"
