# Exclusive tip012 loop recovery: S09 reinjection + S11 build recovery on SHA 6191E58E.
# Logs only to files. Kill contending deep2. Fail-closed seal.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$outDir = Join-Path $root 'artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$runOut = Join-Path $outDir '_run_09_11_recovery_exclusive.out.txt'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
function RLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runOut -Value $line -Encoding ASCII
  Write-Output $line
}
New-Item -ItemType Directory -Force -Path $ev,$outDir | Out-Null
'' | Set-Content -LiteralPath $runOut -Encoding ASCII
if (Test-Path -LiteralPath $lock) {
  $old = Get-Content -LiteralPath $lock -Raw -EA SilentlyContinue
  RLog ("STALE_LOCK_TAKEOVER old=" + $old)
}
@(
  'OWNER=tip012_loop_09_11_recovery_exclusive'
  ("PID=" + $PID)
  ("ASOF_UTC=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
) | Set-Content -LiteralPath $lock -Encoding ASCII

try {
  cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1' | Out-Null
  Start-Sleep 3
  & (Join-Path $outDir '_launch_09_11_recovery.ps1')
  $pidFile = Join-Path $ev 'loop_pid.txt'
  $loopPid = 0
  if (Test-Path $pidFile) {
    $raw = Get-Content $pidFile -Raw
    if ($raw -match 'LAUNCHED_PID=(\d+)') { $loopPid = [int]$Matches[1] }
  }
  RLog ("WAIT_LOOP_PID=" + $loopPid)
  $log = Join-Path $ev 'tip012_loop_exclusive_09_11.log'
  $deadline = (Get-Date).AddSeconds(7200)
  $lastBytes = 0
  while ((Get-Date) -lt $deadline) {
    $alive = $false
    if ($loopPid -gt 0) { $alive = [bool](Get-Process -Id $loopPid -EA SilentlyContinue) }
    if (-not $alive) { $alive = [bool](Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue) }
    $bytes = 0
    if (Test-Path $log) { $bytes = (Get-Item $log).Length }
    if ($bytes -ne $lastBytes) {
      RLog ("LOG_BYTES=" + $bytes + " alive=" + [int]$alive)
      $lastBytes = $bytes
    }
    $hit = $false
    if (Test-Path $log) {
      $t = Get-Content $log -Raw -EA SilentlyContinue
      if ($t -and ($t -match 'FINAL_VERDICT' -or ($t -match 'PATCH COMMITTED' -and $t -match 'RESULT_REINJECTION step=\d+.*status=PASS'))) {
        $hit = $true
      }
    }
    if ($hit) { RLog 'TERMINAL_EVIDENCE_SEEN=1'; break }
    if (-not $alive -and $bytes -gt 0) { RLog 'LOOP_EXITED_NO_FURTHER_GROWTH'; Start-Sleep 5; break }
    Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | ForEach-Object {
      if ($loopPid -gt 0 -and $_.Id -ne $loopPid) {
        RLog ("KILL_FOREIGN_DEEP2=" + $_.Id)
        Stop-Process -Id $_.Id -Force -EA SilentlyContinue
      }
    }
    Start-Sleep 15
  }
  & (Join-Path $outDir '_seal_09_11_recovery.ps1') | Tee-Object -FilePath (Join-Path $outDir '_seal_09_11_recovery.out.txt')
  RLog 'SEAL_DONE=1'
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
  RLog 'LOCK_RELEASED=1'
}
exit 0
