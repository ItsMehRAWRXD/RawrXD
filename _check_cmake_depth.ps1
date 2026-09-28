$content = Get-Content 'f:\~dev\rawrxd\CMakeLists.txt'
$depth = 0
$minDepth = 0
for ($i = 0; $i -lt $content.Count; $i++) {
    $line = $content[$i]
    if ($line -match '^\s*#') { continue }
    $opens = ([regex]::Matches($line, '\bif\s*\(')).Count
    $opens += ([regex]::Matches($line, '\bforeach\s*\(')).Count
    $opens += ([regex]::Matches($line, '\bwhile\s*\(')).Count
    $closes = ([regex]::Matches($line, '\bendif\s*\(\)')).Count
    $closes += ([regex]::Matches($line, '\bendforeach\s*\(\)')).Count
    $closes += ([regex]::Matches($line, '\bendwhile\s*\(\)')).Count
    $depth += $opens - $closes
    if ($depth -lt $minDepth) { $minDepth = $depth }
    if ($depth -lt 0) { Write-Host "NEGATIVE at line $($i+1): $line"; break }
}
Write-Host "Final depth: $depth, Min depth: $minDepth"
