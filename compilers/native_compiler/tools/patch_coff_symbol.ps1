param(
    [string]$ObjPath,
    [string]$SymbolName,
    [int]$NewValue
)

# Patches one COFF symbol's value in place. Used to isolate linker defects
# from defects in the upstream assembler.

$bytes = [System.IO.File]::ReadAllBytes($ObjPath)
$symOff = [BitConverter]::ToUInt32($bytes, 8)
$numSyms = [BitConverter]::ToUInt32($bytes, 12)

for ($i = 0; $i -lt $numSyms; $i++) {
    $so = $symOff + ($i * 18)
    $nbytes = New-Object byte[] 8
    [Array]::Copy($bytes, $so, $nbytes, 0, 8)
    $nm = [System.Text.Encoding]::ASCII.GetString($nbytes).Trim([char]0)
    if ($nm -eq $SymbolName) {
        $old = [BitConverter]::ToUInt32($bytes, $so + 8)
        [BitConverter]::GetBytes([uint32]$NewValue).CopyTo($bytes, $so + 8)
        [System.IO.File]::WriteAllBytes($ObjPath, $bytes)
        Write-Host ("patched '{0}': 0x{1:X} -> 0x{2:X}" -f $SymbolName, $old, $NewValue)
        exit 0
    }
}
Write-Host "symbol '$SymbolName' not found"
exit 1
