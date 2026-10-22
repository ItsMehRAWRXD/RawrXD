param([string]$A, [string]$B)
# Compares the PE headers of two files field by field.
$fa = [System.IO.File]::ReadAllBytes($A)
$fb = [System.IO.File]::ReadAllBytes($B)

function Get-Fields($bytes) {
    $e_lfanew = [BitConverter]::ToUInt32($bytes, 60)
    $coff = $e_lfanew + 4
    $numSec = [BitConverter]::ToUInt16($bytes, $coff + 2)
    $optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
    $opt = $coff + 20
    $f = [ordered]@{}
    $f['Machine'] = '{0:X4}' -f [BitConverter]::ToUInt16($bytes, $coff)
    $f['NumSections'] = $numSec
    $f['SizeOfOptionalHeader'] = $optSize
    $f['Characteristics'] = '{0:X4}' -f [BitConverter]::ToUInt16($bytes, $coff + 18)
    $f['Magic'] = '{0:X4}' -f [BitConverter]::ToUInt16($bytes, $opt)
    $f['SizeOfCode'] = '{0:X}' -f [BitConverter]::ToUInt32($bytes, $opt + 4)
    $f['SizeOfInitData'] = '{0:X}' -f [BitConverter]::ToUInt32($bytes, $opt + 8)
    $f['AddressOfEntryPoint'] = '{0:X8}' -f [BitConverter]::ToUInt32($bytes, $opt + 16)
    $f['BaseOfCode'] = '{0:X8}' -f [BitConverter]::ToUInt32($bytes, $opt + 20)
    $f['ImageBase'] = '{0:X16}' -f [BitConverter]::ToUInt64($bytes, $opt + 24)
    $f['SectionAlignment'] = '{0:X}' -f [BitConverter]::ToUInt32($bytes, $opt + 32)
    $f['FileAlignment'] = '{0:X}' -f [BitConverter]::ToUInt32($bytes, $opt + 36)
    $f['SizeOfImage'] = '{0:X}' -f [BitConverter]::ToUInt32($bytes, $opt + 56)
    $f['SizeOfHeaders'] = '{0:X}' -f [BitConverter]::ToUInt32($bytes, $opt + 60)
    $f['Subsystem'] = [BitConverter]::ToUInt16($bytes, $opt + 68)
    $f['DllCharacteristics'] = '{0:X4}' -f [BitConverter]::ToUInt16($bytes, $opt + 70)
    $f['NumberOfRvaAndSizes'] = [BitConverter]::ToUInt32($bytes, $opt + 108)
    $dirNames = @("Export","Import","Resource","Exception","Security","BaseReloc","Debug",
                  "Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT",
                  "DelayImport","COMDescriptor","Reserved")
    for ($i = 0; $i -lt 16; $i++) {
        $d = $opt + 112 + ($i * 8)
        $rva = [BitConverter]::ToUInt32($bytes, $d)
        $sz = [BitConverter]::ToUInt32($bytes, $d + 4)
        if ($rva -ne 0 -or $sz -ne 0) { $f["Dir[$($dirNames[$i])]"] = ("RVA={0:X8} Size={1:X8}" -f $rva, $sz) }
    }
    $secTab = $opt + $optSize
    for ($i = 0; $i -lt $numSec; $i++) {
        $s = $secTab + ($i * 40)
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
        $f["Sec:$name"] = ("VA={0:X8} VS={1:X8} RawPtr={2:X8} RawSz={3:X8} Chars={4:X8}" -f `
            [BitConverter]::ToUInt32($bytes,$s+12), [BitConverter]::ToUInt32($bytes,$s+8),
            [BitConverter]::ToUInt32($bytes,$s+20), [BitConverter]::ToUInt32($bytes,$s+16),
            [BitConverter]::ToUInt32($bytes,$s+36))
    }
    return $f
}

$fa = Get-Fields $fa
$fb = Get-Fields $fb
$keys = @($fa.Keys) + @($fb.Keys) | Select-Object -Unique
Write-Host ("{0,-24} {1,-42} {2}" -f 'FIELD', 'A', 'B')
Write-Host ("-" -f 100)
foreach ($k in $keys) {
    $va = if ($fa.Contains($k)) { $fa[$k] } else { '-' }
    $vb = if ($fb.Contains($k)) { $fb[$k] } else { '-' }
    $mark = if ($va -eq $vb) { '  ' } else { '**' }
    Write-Host ("{0}{1,-22} {2,-42} {3}" -f $mark, $k, $va, $vb)
}
