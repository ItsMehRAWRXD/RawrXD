$p = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_PE_RUNTIME_001\test_exit42.exe'
$d = [IO.File]::ReadAllBytes($p)
$stub = $d[0xA00..(0xA00+0x1F)]
function Hx($arr) { ($arr | ForEach-Object { $_.ToString('x2') }) -join ' ' }
Write-Output ('stub ' + (Hx $stub))
$mainDisp = [BitConverter]::ToInt32($d, 0xA00 + 5)
$iatDisp = [BitConverter]::ToInt32($d, 0xA00 + 0x0D)
$stubRva = 0x4000
Write-Output ('main_target_rva 0x{0:x}' -f (($stubRva + 9 + $mainDisp) -band 0xFFFFFFFF))
Write-Output ('iat_target_rva 0x{0:x}' -f (($stubRva + 0x11 + $iatDisp) -band 0xFFFFFFFF))
Write-Output ('E8site ' + (Hx $stub[4..8]))
Write-Output ('FF15site ' + (Hx $stub[0x0B..0x10]))
