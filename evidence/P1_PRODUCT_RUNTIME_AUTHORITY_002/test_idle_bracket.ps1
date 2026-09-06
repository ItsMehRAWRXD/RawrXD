$p = Start-Process 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe' -PassThru
foreach ($sec in 5,10,20,30) {
  Start-Sleep -Seconds 5
  Write-Host "t=$sec alive=$(-not $p.HasExited) exit=$($p.ExitCode)"
  if ($p.HasExited) { break }
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
