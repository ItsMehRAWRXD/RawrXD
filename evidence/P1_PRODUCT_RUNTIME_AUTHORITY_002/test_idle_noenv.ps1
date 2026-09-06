$p = Start-Process 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe' -PassThru
Start-Sleep -Seconds 15
Write-Host "alive15=$(-not $p.HasExited) exit=$($p.ExitCode)"
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
