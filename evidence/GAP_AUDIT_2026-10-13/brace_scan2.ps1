$path = "F:\rawrxd\src\deep2\Deep2Engine.cpp"
$lines = Get-Content $path
$depth = 0
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
$firstZeroAfter = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($i -eq 5747) { $depth = 1 }  # at computeAttention's opening line we know depth becomes 1
    $l = $lines[$i]
    $j = 0
    while ($j -lt $l.Length) {
        $c = $l[$j]
        $nx = ""
        if ($j + 1 -lt $l.Length) { $nx = $l[$j+1] }
        if ($inLine) { if ($c -eq "`n") { $inLine = $false }; $j++; continue }
        if ($inBlock) { if ($c -eq "*" -and $nx -eq "/") { $inBlock = $false; $j += 2; continue }; $j++; continue }
        if ($inStr)  { if ($c -eq "\") { $j += 2; continue }; if ($c -eq '"') { $inStr = $false }; $j++; continue }
        if ($inChar) { if ($c -eq "\") { $j += 2; continue }; if ($c -eq "'") { $inChar = $false }; $j++; continue }
        if ($c -eq "/" -and $nx -eq "/") { $inLine = $true; $j += 2; continue }
        if ($c -eq "/" -and $nx -eq "*") { $inBlock = $true; $j += 2; continue }
        if ($c -eq '"') { $inStr = $true; $j++; continue }
        if ($c -eq "'") { $inChar = $true; $j++; continue }
        if ($c -eq "{") { $depth++ }
        elseif ($c -eq "}") { $depth-- }
        $j++
    }
    if ($i -ge 5748 -and $depth -eq 0 -and $firstZeroAfter -lt 0) { $firstZeroAfter = $i + 1; break }
}
"depth-0 line after computeAttention start: $firstZeroAfter"
if ($firstZeroAfter -gt 0) {
    Get-Content $path | Select-Object -Skip ($firstZeroAfter - 4) -First 6 | ForEach-Object { $i++; "[$i] $_" }
}
