$path = "F:\rawrxd\src\deep2\Deep2Engine.cpp"
$lines = Get-Content $path
$depth = 0
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
$found = $false
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
    if ($i -gt 3000 -and $l -match '^[A-Za-z_][A-Za-z0-9_:<>*&\s]+\s+Deep2Engine::' -and $depth -ne 0) {
        "first mis-nested definition at line $($i+1): $($l.Trim().Substring(0,[Math]::Min(80,$l.Trim().Length)))"
        $found = $true
        break
    }
}
if (-not $found) { "no mis-nested definition found" }
