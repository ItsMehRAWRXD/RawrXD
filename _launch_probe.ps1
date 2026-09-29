$exe = "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe"
$log = "F:\~dev\_launch_probe_log.txt"
Remove-Item $log -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $exe -WorkingDirectory "F:\~dev\rawrxd\build_w1\bin\Release" -RedirectStandardOutput $log -RedirectStandardError "F:\~dev\_launch_probe_err.txt" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
if ($p.HasExited) { "EXITED code=$($p.ExitCode)" } else { "RUNNING pid=$($p.Id)"; Stop-Process -Id $p.Id -Force }
Get-Content $log -TotalCount 40 -ErrorAction SilentlyContinue
"--- stderr ---"
Get-Content "F:\~dev\_launch_probe_err.txt" -TotalCount 20 -ErrorAction SilentlyContinue
