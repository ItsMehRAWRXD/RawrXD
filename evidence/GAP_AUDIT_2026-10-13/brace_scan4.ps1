$path = "F:\rawrxd\src\deep2\Deep2Engine.cpp"
$lines = Get-Content $path
$depth = 1
$inStr = $false; $inChar = $false; $inLine = $false; $inBlock = $false
for ($i = 5747; $i -lt 6458; $i++) {
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
    if ($t -match '^(\}|\}|for |while |if |} else \{|else \{)|^\}\s*$|^if \(|^for \(|if \(.*\)$|else$|^\}$') {
        $short = if ($t.Length -gt 60) { $t.Substring(0,60) } else { $t }
        "{0,5} d={1} :: {2}" -f ($i+1), $depth, $short
    }
}
