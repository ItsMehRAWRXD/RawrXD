param([string]$Path, [int]$Offset, [int]$Count = 96)
$bytes = [System.IO.File]::ReadAllBytes($Path)
$end = [Math]::Min($Offset + $Count, $bytes.Length)
for ($i = $Offset; $i -lt $end; $i += 16) {
    $hex = ''
    $asc = ''
    for ($j = 0; $j -lt 16; $j++) {
        if ($i + $j -lt $bytes.Length) {
            $hex += ("{0:X2} " -f $bytes[$i + $j])
            $c = [char]$bytes[$i + $j]
            if ($c -match '[ -~]') { $asc += $c } else { $asc += '.' }
        }
    }
    Write-Host ("{0:X8}: {1}  {2}" -f $i, $hex, $asc)
}
