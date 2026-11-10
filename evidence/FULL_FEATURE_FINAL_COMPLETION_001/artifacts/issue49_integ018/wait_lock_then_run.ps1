# Wait for ISSUE49 exclusive lock, then run tip018 clean exclusive.
$ErrorActionPreference = 'Continue'
$waitLog = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ018\_wait_lock.log"
$lock = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock"
$runner = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ018\run_tip018_clean_exclusive.ps1"
"WAIT_START $(Get-Date -Format o)" | Set-Content $waitLog
$maxMin = 90
for ($i = 0; $i -lt $maxMin; $i++) {
  if (-not (Test-Path $lock)) {
    "LOCK_FREE t=${i}m $(Get-Date -Format o)" | Add-Content $waitLog
    break
  }
  $owner = (Get-Content $lock -Raw -EA SilentlyContinue)
  $pidLine = ($owner -split "`n" | Where-Object { $_ -match '^PID=' } | Select-Object -First 1)
  $ownDeep = ($owner -split "`n" | Where-Object { $_ -match '^OWN_DEEP2=' } | Select-Object -First 1)
  $psPid = if ($pidLine) { [int]($pidLine -replace 'PID=','') } else { 0 }
  $loopPid = if ($ownDeep) { [int]($ownDeep -replace 'OWN_DEEP2=','') } else { 0 }
  $alivePs = if ($psPid -gt 0) { [bool](Get-Process -Id $psPid -EA SilentlyContinue) } else { $false }
  $aliveLoop = if ($loopPid -gt 0) { [bool](Get-Process -Id $loopPid -EA SilentlyContinue) } else { $false }
  "WAIT t=${i}m alive_ps=$alivePs($psPid) alive_loop=$aliveLoop($loopPid)" | Add-Content $waitLog
  if (-not $alivePs -and -not $aliveLoop) {
    "STALE_LOCK_CLEAR $(Get-Date -Format o)" | Add-Content $waitLog
    Remove-Item $lock -Force -EA SilentlyContinue
    break
  }
  Start-Sleep -Seconds 60
}
if (Test-Path $lock) {
  "ABORT_STILL_LOCKED $(Get-Date -Format o)" | Add-Content $waitLog
  exit 9
}
"LAUNCH $(Get-Date -Format o)" | Add-Content $waitLog
& powershell -NoProfile -ExecutionPolicy Bypass -File $runner *>> $waitLog
$ec = $LASTEXITCODE
"DONE exit=$ec $(Get-Date -Format o)" | Add-Content $waitLog
exit $(if ($null -eq $ec) { 1 } else { $ec })
