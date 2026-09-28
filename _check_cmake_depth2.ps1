$content = Get-Content 'f:\~dev\rawrxd\CMakeLists.txt'
$depth = 0
$lines = @()
for ($i = 0; $i -lt $content.Count; $i++) {
    $line = $content[$i]
    if ($line -match '^\s*#') { continue }
    $opens = ([regex]::Matches($line, '\bif\s*\(')).Count
    $opens += ([regex]::Matches($line, '\bforeach\s*\(')).Count
    $opens += ([regex]::Matches($line, '\bwhile\s*\(')).Count
    $closes = ([regex]::Matches($line, '\bendif\s*\(\)')).Count
    $closes += ([regex]::Matches($line, '\bendforeach\s*\(\)')).Count
    $closes += ([regex]::Matches($line, '\bendwhile\s*\(\)')).Count
    $prevDepth = $depth
    $depth += $opens - $closes
    if ($prevDepth -eq 0 -and $depth -gt 0) {
        $lines += "Enter block at line $($i+1): $line"
        if ($lines.Count -gt 200) { break }
    }
    if ($prevDepth -gt 0 -and $depth -eq 0 -and $lines.Count -gt 0) {
        $lines += "Close block at line $($i+1): $line"
    }
}
$lines | Set-Content 'f:\~dev\_cmake_block_trace.txt'
Write-Host "Wrote $($lines.Count) transitions to _cmake_block_trace.txt"
