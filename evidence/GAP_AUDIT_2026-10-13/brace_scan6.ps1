$path = "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\engine_preprocessed.i"
$lines = Get-Content $path
$depth = 0
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
$firstBad = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
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
    $t = $l.Trim()
    if ($t -match 'Deep2Engine::[A-Za-z_]+\s*\(' -and -not $t.StartsWith("//") -and $depth -ne 0 -and $firstBad -lt 0) {
        $firstBad = $i + 1
        "first function at nonzero depth: preprocessed line $firstBad (depth=$depth)"
        "  : $($t.Substring(0,[Math]::Min(90,$t.Length)))"
    }
}
"final depth: $depth"
