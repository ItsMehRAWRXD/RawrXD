Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
$pkg = 'F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_001\RawrXD-Win32IDE-Native-Ext.exe'
$broken = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$env:RAWRXD_LOG_DIR = 'F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_001_fp2'
$env:RAWRXD_PROBLEMS_FIXTURE = $broken
New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
$p = Start-Process -FilePath $pkg -ArgumentList @($broken) -PassThru -WindowStyle Normal
Write-Host "PID=$($p.Id)"
$gotMain = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) {
    Write-Host "EXIT t=$i code=$($p.ExitCode) gotMain=$gotMain"
    break
  }
  if (-not $gotMain -and $p.MainWindowHandle -ne 0) {
    $gotMain = $true
    Write-Host "MAIN t=$i hwnd=$($p.MainWindowHandle)"
  }
}
if (-not $p.HasExited) {
  Write-Host "ALIVE_FINAL hwnd=$($p.MainWindowHandle)"
  Stop-Process -Id $p.Id -Force -EA SilentlyContinue
}
Get-Content 'F:\rawrxd\startup_trace.log' -Tail 20
