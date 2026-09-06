$path = 'F:\~dev\rawrxd\build-win32ide-fresh\bin\crash_dumps\RawrXD_20260901_212315_C0000005.dmp'
$fs = [IO.File]::OpenRead($path)
$br = New-Object IO.BinaryReader($fs)
$fs.Position = 8
[void]$br.ReadUInt32() # ver
$n = $br.ReadUInt32()
$dir = $br.ReadUInt32()
$fs.Position = $dir
for ($i=0; $i -lt $n; $i++) {
  $t = $br.ReadUInt32()
  $sz = $br.ReadUInt32()
  $rva = $br.ReadUInt32()
  Write-Host "stream type=$t size=$sz rva=$rva"
}
$br.Close(); $fs.Close()
