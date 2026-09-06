$path = 'F:\~dev\rawrxd\build-win32ide-fresh\bin\crash_dumps\RawrXD_20260901_212315_C0000005.dmp'
$b = [IO.File]::ReadAllBytes($path)
for ($row=0; $row -lt 8; $row++) {
  $off = $row * 16
  $hex = ($b[$off..($off+15)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
  Write-Host ('{0:X8}  {1}' -f $off, $hex)
}
