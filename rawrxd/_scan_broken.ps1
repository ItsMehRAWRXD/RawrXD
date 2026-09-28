$content = Get-Content 'F:\~dev\rawrxd\CMakeLists.txt' -Raw
$pattern = '(?s)add_executable\((\w+)\s+(?:EXCLUDE_FROM_ALL\s+)?(.*?)(?:\r?\n\))'
$matches = [regex]::Matches($content, $pattern)
$broken = @()
foreach ($m in $matches) {
    $target = $m.Groups[1].Value
    $srcBlock = $m.Groups[2].Value
    $srcPaths = [regex]::Matches($srcBlock, '(?:src|tests|B014)/[^\s\)]+|[^\s\)]+\.cpp')
    $anyExists = $false
    foreach ($sp in $srcPaths) {
        $path = $sp.Value
        $full = Join-Path 'F:\~dev\rawrxd' ($path -replace '/','\')
        if (Test-Path $full -PathType Leaf) {
            $anyExists = $true
            break
        }
    }
    if (-not $anyExists) {
        $broken += $target
    }
}
$broken
