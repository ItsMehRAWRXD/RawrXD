$pp = "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\engine_preprocessed.i"
$lines = Get-Content $pp
# find the preprocessed line where Deep2Engine.cpp's own body starts
$startIdx = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '#line\s+1\s+"src.deep2.Deep2Engine.cpp"') { $startIdx = $i; break }
}
if ($startIdx -lt 0) {
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Deep2Engine\.cpp"') { $startIdx = $i; break }
    }
}
"cpp section starts at preprocessed line: $($startIdx+1)"
$depth = 0
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
$reported = 0
for ($i = $startIdx; $i -lt $lines.Count; $i++) {
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
    if ($t -match 'Deep2Engine::[A-Za-z_]+\s*\(' -and $depth -ne 0 -and $reported -lt 5) {
        $reported++
        "def at depth $depth : $($t.Substring(0,[Math]::Min(80,$t.Length)))"
    }
}
"final depth: $depth"
