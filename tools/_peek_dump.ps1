$path = 'F:\~dev\rawrxd\build-win32ide-fresh\bin\crash_dumps\RawrXD_20260901_212315_C0000005.dmp'
$b = [IO.File]::ReadAllBytes($path)
Write-Host "len=$($b.Length)"
Write-Host ("sig=0x{0:X8}" -f [BitConverter]::ToUInt32($b,0))
Write-Host ("streams=$([BitConverter]::ToUInt32($b,8))")
Write-Host ("dirRva=$([BitConverter]::ToUInt32($b,12))")
