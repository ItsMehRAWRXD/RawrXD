$path = "F:\rawrxd\src\deep2\Deep2Engine.cpp"
$lines = Get-Content $path
$depth = 1
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
$prev = 1
for ($i = 5747; $i -lt 6458; $i++) {
    $l = $lines[$i]
    $j = 0
    $startDepth = $depth
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
        if ($c -eq '"") { $inStr = $true; $j++; continue }
        if ($c -eq "'") { $inChar = $true; $j++; continue }
        if ($c -eq "{") { $depth++ }
        elseif ($c -eq "}") { $depth-- }
        $j++
    }
    if ($startDepth -ne $depth) {
        $t = $l.Trim()
        $short = if ($t.Length -gt 70) { $t.Substring(0,70) } else { $t }
        "{0,5} {1}->{2} :: {3}" -f ($i+1), $startDepth, $depth, $short
    }
}
