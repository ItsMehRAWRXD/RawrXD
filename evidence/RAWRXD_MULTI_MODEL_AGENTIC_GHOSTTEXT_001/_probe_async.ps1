$ErrorActionPreference = 'Continue'
$bin = 'G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin'
$ev = 'G:\~dev\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001'
Get-Process -Name 'RawrXD-Win32IDE' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-Item -LiteralPath (Join-Path $bin 'feature_probe_last.txt') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $bin 'feature_probe_breadcrumb.txt') -Force -ErrorAction SilentlyContinue
$p = Start-Process -FilePath (Join-Path $bin 'RawrXD-Win32IDE.exe') -ArgumentList '--test-ghost-text' -WorkingDirectory $bin -PassThru
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if (Test-Path -LiteralPath (Join-Path $bin 'feature_probe_last.txt')) { break }
  if ($p.HasExited) { break }
  Start-Sleep -Milliseconds 500
}
if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}
$exit = if ($p.HasExited) { $p.ExitCode } else { 'KILLED_TIMEOUT' }
Set-Content -LiteralPath (Join-Path $ev 'FREEZE_748B_PROBE_exit.txt') -Value ("EXIT=" + $exit) -Encoding ASCII
if (Test-Path -LiteralPath (Join-Path $bin 'feature_probe_last.txt')) {
  Copy-Item -LiteralPath (Join-Path $bin 'feature_probe_last.txt') -Destination (Join-Path $ev 'FREEZE_748B_PROBE_last.txt') -Force
}
if (Test-Path -LiteralPath (Join-Path $bin 'feature_probe_breadcrumb.txt')) {
  Copy-Item -LiteralPath (Join-Path $bin 'feature_probe_breadcrumb.txt') -Destination (Join-Path $ev 'FREEZE_748B_PROBE_breadcrumb.txt') -Force
}
'ASYNC_PROBE_DONE' | Set-Content -LiteralPath (Join-Path $ev 'FREEZE_748B_PROBE_async_done.txt') -Encoding ASCII
