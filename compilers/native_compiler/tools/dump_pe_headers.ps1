param([string]$Path)

$bytes = [System.IO.File]::ReadAllBytes($Path)
$e_lfanew = [BitConverter]::ToUInt32($bytes, 60)
$coff = $e_lfanew + 4
$numSections = [BitConverter]::ToUInt16($bytes, $coff + 2)
$optSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
$opt = $coff + 20
$secTab = $opt + $optSize

Write-Host "=== COFF ==="
Write-Host ("  Machine=0x{0:X4} Sections={1} OptHdrSize={2} Characteristics=0x{3:X4}" -f `
    [BitConverter]::ToUInt16($bytes, $coff), $numSections, $optSize, [BitConverter]::ToUInt16($bytes, $coff + 18))

Write-Host "=== Optional Header (PE32+) ==="
Write-Host ("  Magic=0x{0:X4} LinkerVer={1}.{2}" -f [BitConverter]::ToUInt16($bytes, $opt), $bytes[$opt+2], $bytes[$opt+3])
Write-Host ("  SizeOfCode=0x{0:X} SizeOfInitData=0x{1:X} SizeOfUninitData=0x{2:X}" -f `
    [BitConverter]::ToUInt32($bytes, $opt+4), [BitConverter]::ToUInt32($bytes, $opt+8), [BitConverter]::ToUInt32($bytes, $opt+12))
Write-Host ("  EntryPoint=0x{0:X8} BaseOfCode=0x{1:X8}" -f `
    [BitConverter]::ToUInt32($bytes, $opt+16), [BitConverter]::ToUInt32($bytes, $opt+20))
Write-Host ("  ImageBase=0x{0:X16}" -f [BitConverter]::ToUInt64($bytes, $opt+24))
Write-Host ("  SectionAlign=0x{0:X} FileAlign=0x{1:X}" -f `
    [BitConverter]::ToUInt32($bytes, $opt+32), [BitConverter]::ToUInt32($bytes, $opt+36))
Write-Host ("  SizeOfImage=0x{0:X} SizeOfHeaders=0x{1:X} Checksum=0x{2:X}" -f `
    [BitConverter]::ToUInt32($bytes, $opt+56), [BitConverter]::ToUInt32($bytes, $opt+60), [BitConverter]::ToUInt32($bytes, $opt+64))
Write-Host ("  Subsystem={0} DllCharacteristics=0x{1:X4}" -f `
    [BitConverter]::ToUInt16($bytes, $opt+68), [BitConverter]::ToUInt16($bytes, $opt+70))
Write-Host ("  StackReserve=0x{0:X} StackCommit=0x{1:X}" -f `
    [BitConverter]::ToUInt64($bytes, $opt+72), [BitConverter]::ToUInt64($bytes, $opt+80))
Write-Host ("  HeapReserve=0x{0:X} HeapCommit=0x{1:X}" -f `
    [BitConverter]::ToUInt64($bytes, $opt+88), [BitConverter]::ToUInt64($bytes, $opt+96))
Write-Host ("  NumberOfRvaAndSizes={0}" -f [BitConverter]::ToUInt32($bytes, $opt+108))

$dirNames = @("Export","Import","Resource","Exception","Security","BaseReloc","Debug","Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT","DelayImport","COMDescriptor","Reserved")
Write-Host "=== Data Directories ==="
$numDirs = [BitConverter]::ToUInt32($bytes, $opt+108)
for ($i = 0; $i -lt [Math]::Min($numDirs,16); $i++) {
    $d = $opt + 112 + ($i*8)
    $rva = [BitConverter]::ToUInt32($bytes, $d)
    $sz = [BitConverter]::ToUInt32($bytes, $d+4)
    if ($rva -ne 0 -or $sz -ne 0) {
        Write-Host ("  [{0,2}] {1,-14} RVA=0x{2:X8} Size=0x{3:X8}" -f $i, $dirNames[$i], $rva, $sz)
    }
}

Write-Host "=== Sections ==="
for ($i = 0; $i -lt $numSections; $i++) {
    $s = $secTab + ($i*40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).Trim([char]0)
    $ch = [BitConverter]::ToUInt32($bytes, $s+36)
    $flags = @()
    if ($ch -band 0x20) { $flags += "CODE" }
    if ($ch -band 0x40) { $flags += "IDATA" }
    if ($ch -band 0x80) { $flags += "UDATA" }
    if ($ch -band 0x20000000) { $flags += "X" }
    if ($ch -band 0x40000000) { $flags += "R" }
    if ($ch -band 0x80000000) { $flags += "W" }
    Write-Host ("  {0,-10} VA=0x{1:X8} VS=0x{2:X8} RawSz=0x{3:X8} RawPtr=0x{4:X8} Chars=0x{5:X8} [{6}]" -f `
        $name, [BitConverter]::ToUInt32($bytes,$s+12), [BitConverter]::ToUInt32($bytes,$s+8), `
        [BitConverter]::ToUInt32($bytes,$s+16), [BitConverter]::ToUInt32($bytes,$s+20), $ch, ($flags -join ","))
}
