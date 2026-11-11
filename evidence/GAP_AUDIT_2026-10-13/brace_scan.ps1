$path = "F:\rawrxd\src\deep2\Deep2Engine.cpp"
$lines = Get-Content $path
$depth = 0
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
$boundaries = New-Object System.Collections.Generic.List[string]
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
        elseif ($c -eq "}") { $depth--; if ($depth -lt 0) { $boundaries.Add("NEGATIVE DEPTH at line $($i+1)"); $depth = 0 } }
        $j++
    }
    if ($depth -eq 0 -and $l -match 'Deep2Engine::[A-Za-z_]+\s*\(') { $boundaries.Add("depth0 fn at $($i+1): $($l.Trim().Substring(0, [Math]::Min(70, $l.Trim().Length)))") }
}
$boundaries | Select-Object -Last 8
"FINAL DEPTH: $depth"
