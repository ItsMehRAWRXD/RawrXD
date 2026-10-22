param([string]$Exe)
# Finds the call site that references a given format string and prints the
# instructions that precede it.
$bytes = [System.IO.File]::ReadAllBytes($Exe)
$e_lfanew = [BitConverter]::ToUInt32($bytes, 60)
$coff = $e_lfanew + 4
$numSec = [BitConverter]::ToUInt16($bytes, $coff + 2)
$optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
$opt = $coff + 20
$secTab = $opt + $optSize
$imageBase = [BitConverter]::ToUInt64($bytes, $opt + 24)

# Find the string in the file.
$needle = [System.Text.Encoding]::ASCII.GetBytes("fn(%d, %d)")
$strFileOff = -1
for ($i = 0; $i -lt $bytes.Length - $needle.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $needle.Length; $j++) {
        if ($bytes[$i + $j] -ne $needle[$j]) { $match = $false; break }
    }
    if ($match) { $strFileOff = $i; break }
}
if ($strFileOff -lt 0) { Write-Host "string not found"; exit 1 }

# Map the file offset to an RVA.
$strRva = 0
for ($i = 0; $i -lt $numSec; $i++) {
    $s = $secTab + ($i * 40)
    $va = [BitConverter]::ToUInt32($bytes, $s + 12)
    $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
    $rawSz = [BitConverter]::ToUInt32($bytes, $s + 16)
    if ($strFileOff -ge $raw -and $strFileOff -lt ($raw + $rawSz)) {
        $strRva = $va + ($strFileOff - $raw)
        Write-Host ("string '{0}' at file 0x{1:X} RVA 0x{2:X8}" -f "fn(%d, %d)", $strFileOff, $strRva)
        break
    }
}

# Search the .text for `lea rcx, [rip+disp]` that targets the string.
for ($i = 0; $i -lt $numSec; $i++) {
    $s = $secTab + ($i * 40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
    if ($name -ne '.text') { continue }
    $va = [BitConverter]::ToUInt32($bytes, $s + 12)
    $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
    $rawSz = [BitConverter]::ToUInt32($bytes, $s + 16)
    for ($k = 0; $k + 7 -le $rawSz; $k++) {
        if ($bytes[$raw + $k] -eq 0x48 -and $bytes[$raw + $k + 1] -eq 0x8D -and
            $bytes[$raw + $k + 2] -eq 0x0D) {
            $disp = [BitConverter]::ToInt32($bytes, $raw + $k + 3)
            $next = $va + $k + 7
            $target = $next + $disp
            if ($target -eq $strRva) {
                Write-Host ("--- call site for the fn() printf at RVA 0x{0:X8} ---" -f ($va + $k))
                # Print the 60 bytes before this instruction.
                $start = [Math]::Max(0, $k - 60)
                for ($b = $start; $b -lt $k + 7; $b += 16) {
                    $hex = ''
                    $asc = ''
                    for ($c = 0; $c -lt 16; $c++) {
                        if ($b + $c -lt $rawSz) {
                            $byte = $bytes[$raw + $b + $c]
                            $hex += ("{0:X2} " -f $byte)
                            $ch = [char]$byte
                            if ($ch -match '[ -~]') { $asc += $ch } else { $asc += '.' }
                        }
                    }
                    Write-Host ("  {0:X8}: {1}  {2}" -f ($va + $b), $hex, $asc)
                }
            }
        }
    }
}
