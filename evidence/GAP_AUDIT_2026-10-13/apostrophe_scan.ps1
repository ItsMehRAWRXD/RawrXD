$path = "F:\rawrxd\src\deep2\Deep2Engine.cpp"
$lines = Get-Content $path
for ($i = 0; $i -lt $lines.Count; $i++) {
    $t = $lines[$i].Trim()
    if ($t.Length -eq 0) { continue }
    if ($t.StartsWith("//")) { continue }
    # count single quotes not part of an obvious 'x' literal pair
    $q = 0
    $inDq = $false
    for ($k = 0; $k -lt $t.Length; $k++) {
        $ch = $t[$k]
        if ($ch -eq '"') { $inDq = -not $inDq; continue }
        if ($ch -eq "'" -and -not $inDq) { $q++ }
    }
    if ($q -ne 0) {
        $short = if ($t.Length -gt 110) { $t.Substring(0,110) } else { $t }
        "{0,5} q={1} :: {2}" -f ($i+1), $q, $short
    }
}
