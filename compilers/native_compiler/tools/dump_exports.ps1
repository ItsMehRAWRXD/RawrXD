param([string]$Path)
# Dumps the export directory of a PE file.
$bytes = [System.IO.File]::ReadAllBytes($Path)
$e_lfanew = [BitConverter]::ToUInt32($bytes, 60)
$coff = $e_lfanew + 4
$numSec = [BitConverter]::ToUInt16($bytes, $coff + 2)
$optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
$opt = $coff + 20
$secTab = $opt + $optSize

$expRva = [BitConverter]::ToUInt32($bytes, $opt + 112)
$expSize = [BitConverter]::ToUInt32($bytes, $opt + 116)
Write-Host ("Export directory RVA=0x{0:X8} Size=0x{1:X8}" -f $expRva, $expSize)

$secVa = 0; $secRaw = 0; $secVs = 0
for ($i = 0; $i -lt $numSec; $i++) {
    $s = $secTab + ($i * 40)
    $va = [BitConverter]::ToUInt32($bytes, $s + 12)
    $vs = [BitConverter]::ToUInt32($bytes, $s + 8)
    $raw = [BitConverter]::ToUInt32($bytes, $s + 20)
    if ($expRva -ge $va -and $expRva -lt ($va + [Math]::Max($vs, 0x1000))) {
        $secVa = $va; $secRaw = $raw; $secVs = $vs
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
        Write-Host ("  in section {0} VA=0x{1:X8} Raw=0x{2:X8} VS=0x{3:X8}" -f $name, $va, $raw, $vs)
    }
}
if ($secRaw -eq 0) { Write-Host "  export directory not mapped"; exit 1 }

$dirOff = $secRaw + ($expRva - $secVa)
function ToOff([uint32]$rva) { return $secRaw + [int]($rva - $secVa) }
function Str($rva) {
    $o = ToOff $rva
    $s = ''
    while ($o -lt $bytes.Length -and $bytes[$o] -ne 0) { $s += [char]$bytes[$o]; $o++ }
    return $s
}

Write-Host ("  Characteristics   = 0x{0:X8}" -f [BitConverter]::ToUInt32($bytes, $dirOff + 0))
Write-Host ("  TimeDateStamp     = 0x{0:X8}" -f [BitConverter]::ToUInt32($bytes, $dirOff + 4))
Write-Host ("  MajorVersion      = 0x{0:X8}" -f [BitConverter]::ToUInt32($bytes, $dirOff + 8))
Write-Host ("  MinorVersion      = 0x{0:X8}" -f [BitConverter]::ToUInt32($bytes, $dirOff + 12))
$nameRva = [BitConverter]::ToUInt32($bytes, $dirOff + 16)
Write-Host ("  Name              = 0x{0:X8} '{1}'" -f $nameRva, (Str $nameRva))
$base = [BitConverter]::ToUInt32($bytes, $dirOff + 20)
$nFunc = [BitConverter]::ToUInt32($bytes, $dirOff + 24)
$nName = [BitConverter]::ToUInt32($bytes, $dirOff + 28)
$afRva = [BitConverter]::ToUInt32($bytes, $dirOff + 32)
$anRva = [BitConverter]::ToUInt32($bytes, $dirOff + 36)
$anoRva = [BitConverter]::ToUInt32($bytes, $dirOff + 40)
Write-Host ("  Base              = {0}" -f $base)
Write-Host ("  NumberOfFunctions = {0}" -f $nFunc)
Write-Host ("  NumberOfNames     = {0}" -f $nName)
Write-Host ("  AddressOfFunctions     = 0x{0:X8}" -f $afRva)
Write-Host ("  AddressOfNames         = 0x{0:X8}" -f $anRva)
Write-Host ("  AddressOfNameOrdinals  = 0x{0:X8}" -f $anoRva)

for ($i = 0; $i -lt $nFunc; $i++) {
    $f = [BitConverter]::ToUInt32($bytes, (ToOff $afRva) + $i * 4)
    Write-Host ("    func[{0}] rva=0x{1:X8}" -f $i, $f)
}
for ($i = 0; $i -lt $nName; $i++) {
    $nr = [BitConverter]::ToUInt32($bytes, (ToOff $anRva) + $i * 4)
    $ord = [BitConverter]::ToUInt16($bytes, (ToOff $anoRva) + $i * 2)
    Write-Host ("    name[{0}] rva=0x{1:X8} '{2}' ordinal={3}" -f $i, $nr, (Str $nr), $ord)
}
