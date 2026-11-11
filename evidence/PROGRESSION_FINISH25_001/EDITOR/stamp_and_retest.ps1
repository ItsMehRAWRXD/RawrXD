#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$p = 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\EDITOR\finish25_t17_t07_t08_t10.ps1'
$sha = (Get-FileHash -LiteralPath 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe' -Algorithm SHA256).Hash
$c = [IO.File]::ReadAllText($p)
foreach ($old in @(
  'PLACEHOLDER_SHA_PENDING',
  '1ADAD11005734658163956DC4CBB8445A1ED78556A5DB3E4951BEACB5C388107',
  '306CE30C03052844480FC1F8B88CC11D935939172768749ED82F220EE6EAE7AC',
  '323A38A0849EFDE08F735EF85D97009D68C4700C9670317FCC2B630E85580E37'
)) {
  $c = $c.Replace($old, $sha)
}
[IO.File]::WriteAllText($p, $c)
Write-Host "EXPECTED_SHA=$sha"
& $p
