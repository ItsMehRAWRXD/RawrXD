$path = 'F:\~dev\rawrxd\build-win32ide-fresh\bin\crash_dumps\RawrXD_20260901_212315_C0000005.dmp'
$b = [IO.File]::ReadAllBytes($path)
$modOff = 0x880
$nmod = [BitConverter]::ToUInt32($b, $modOff)
foreach ($i in 0..($nmod-1)) {
  $m = $modOff + 4 + $i * 108
  $base = [BitConverter]::ToUInt64($b, $m)
  $size = [BitConverter]::ToUInt32($b, $m + 8)
  $nameRva = [BitConverter]::ToUInt32($b, $m + 20)
  $nameBytes = @()
  $np = $nameRva
  while ($np -lt $b.Length - 1) {
    $ch = [BitConverter]::ToUInt16($b, $np)
    $np += 2
    if ($ch -eq 0) { break }
    $nameBytes += [byte]($ch -band 0xFF)
    $nameBytes += [byte](($ch -shr 8) -band 0xFF)
  }
  $name = [Text.Encoding]::Unicode.GetString([byte[]]$nameBytes)
  if ($base -lt 0x10000000 -or $name -match 'RawrXD|Win32IDE|atiadl|vcruntime|msvcp') {
    Write-Host ("{0} base=0x{1:X} size=0x{2:X}" -f $name, $base, $size)
  }
}
