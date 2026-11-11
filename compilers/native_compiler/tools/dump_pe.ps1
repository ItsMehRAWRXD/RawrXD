param([string]$Path)

$bytes = [System.IO.File]::ReadAllBytes($Path)

function Dump-Hex {
    param([byte[]]$Data, [int]$Offset, [int]$Count, [uint32]$Base)
    for ($k = 0; $k -lt $Count; $k += 16) {
        $hex = ''
        $asc = ''
        for ($j = 0; $j -lt 16 -and ($k + $j) -lt $Count; $j++) {
            $b = $Data[$Offset + $k + $j]
            $hex += ("{0:X2} " -f $b)
            $c = [char]$b
            if ($c -match '[ -~]') { $asc += $c } else { $asc += '.' }
        }
        Write-Host ("  {0:X8}: {1}  {2}" -f ($Base + $k), $hex, $asc)
    }
}

if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
    $e_lfanew = [BitConverter]::ToUInt32($bytes, 60)
    $coff = $e_lfanew + 4
    $numSections = [BitConverter]::ToUInt16($bytes, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
    $opt = $coff + 20
    $secTab = $opt + $optSize
    $entry = [BitConverter]::ToUInt32($bytes, $opt + 16)
    $imageBase = [BitConverter]::ToUInt64($bytes, $opt + 24)
    Write-Host ("PE entry RVA=0x{0:X8} imageBase=0x{1:X16}" -f $entry, $imageBase)
    for ($i = 0; $i -lt $numSections; $i++) {
        $s = $secTab + ($i * 40)
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
        $vs = [BitConverter]::ToUInt32($bytes, $s + 8)
        $va = [BitConverter]::ToUInt32($bytes, $s + 12)
        $rs = [BitConverter]::ToUInt32($bytes, $s + 16)
        $ro = [BitConverter]::ToUInt32($bytes, $s + 20)
        Write-Host ("section {0,-10} VA=0x{1:X8} VS=0x{2:X8} Raw=0x{3:X8}@{4:X8}" -f $name, $va, $vs, $rs, $ro)
        if ($name -eq '.text' -or $name -eq '.idata' -or $name -eq '.edata' -or $name -eq '.data' -or $name -eq '.rdata') {
            $n = [Math]::Min([int]$vs, 128)
            if ($n -gt 0) { Dump-Hex -Data $bytes -Offset $ro -Count $n -Base $va }
        }
    }
} else {
    $numSections = [BitConverter]::ToUInt16($bytes, 2)
    $symOff = [BitConverter]::ToUInt32($bytes, 8)
    $numSyms = [BitConverter]::ToUInt32($bytes, 12)
    $secTab = 20
    for ($i = 0; $i -lt $numSections; $i++) {
        $s = $secTab + ($i * 40)
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
        $rs = [BitConverter]::ToUInt32($bytes, $s + 16)
        $ro = [BitConverter]::ToUInt32($bytes, $s + 20)
        $rc = [BitConverter]::ToUInt32($bytes, $s + 32)
        Write-Host ("section {0,-10} RawSize=0x{1:X8} RawOff=0x{2:X8} relocs={3}" -f $name, $rs, $ro, $rc)
        if ($name -eq '.text') {
            Dump-Hex -Data $bytes -Offset $ro -Count $rs -Base 0
            $relOff = $ro + $rs
            for ($r = 0; $r -lt $rc; $r++) {
                $ro2 = $relOff + ($r * 10)
                $va = [BitConverter]::ToUInt32($bytes, $ro2)
                $si = [BitConverter]::ToUInt32($bytes, $ro2 + 4)
                $ty = [BitConverter]::ToUInt16($bytes, $ro2 + 8)
                Write-Host ("  reloc off=0x{0:X} sym={1} type={2}" -f $va, $si, $ty)
            }
        }
    }
    Write-Host "symbols:"
    for ($i = 0; $i -lt $numSyms; $i++) {
        $so = $symOff + ($i * 18)
        $nbytes = New-Object byte[] 8
        [Array]::Copy($bytes, $so, $nbytes, 0, 8)
        $nm = [System.Text.Encoding]::ASCII.GetString($nbytes).Trim([char]0)
        $val = [BitConverter]::ToUInt32($bytes, $so + 8)
        $sec = [BitConverter]::ToUInt16($bytes, $so + 12)
        $cls = $bytes[$so + 16]
        if ($nm) { Write-Host ("  [{0}] {1,-16} val=0x{2:X} sec={3} class={4}" -f $i, $nm, $val, $sec, $cls) }
    }
}
