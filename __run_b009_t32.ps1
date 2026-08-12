$env:RAWRXD_BACKEND_MODE="cpu-only"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$proc = Start-Process -FilePath "d:\rawrxd\build-ninja\bin\rawrxd.exe" -ArgumentList "--model","d:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf","--prompt","Hello","--benchmark-t","32","--verbose" -RedirectStandardOutput "d:\rawrxd\__b009_t32.log" -RedirectStandardError "d:\rawrxd\__b009_t32.err" -PassThru -Wait
$sw.Stop()
Write-Host "EXIT CODE: $($proc.ExitCode)"
Write-Host "WALL TIME: $($sw.Elapsed.TotalSeconds)s"
Write-Host "--- STDOUT (last 60) ---"
Get-Content "d:\rawrxd\__b009_t32.log" -ErrorAction SilentlyContinue | Select-Object -Last 60
Write-Host "--- STDERR ---"
Get-Content "d:\rawrxd\__b009_t32.err" -ErrorAction SilentlyContinue | Select-Object -Last 20
