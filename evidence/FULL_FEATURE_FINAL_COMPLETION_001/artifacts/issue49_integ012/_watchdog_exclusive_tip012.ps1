# Kill any non-tip012-s11 deep2 / freeze pin for duration. Own loop identified by workdir marker.
param([int]$Minutes = 20, [int]$OwnLoopPid = 0)
$ErrorActionPreference = 'Continue'
$deadline = (Get-Date).AddMinutes($Minutes)
$log = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\_watchdog_exclusive_tip012.out.txt'
'' | Set-Content $log -Encoding ASCII
function W([string]$m) { Add-Content $log ("$(Get-Date -Format o) $m") }
W ("START own=" + $OwnLoopPid)
while ((Get-Date) -lt $deadline) {
  Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and (
      $_.CommandLine -match 'issue49_s13_s15|_s15_tip015|integ015_remeasure|RXD_PIN_A190' -or
      ($_.Name -eq 'deep2_agentic_loop.exe' -and $_.ProcessId -ne $OwnLoopPid -and $_.CommandLine -notmatch 's11_agent_owned_')
    )
  } | ForEach-Object {
    W ("KILL=" + $_.ProcessId + " " + $_.Name)
    Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
  }
  # If OwnLoopPid unknown, protect tip012 ollama provider loops in issue49_integ012 only
  Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | ForEach-Object {
    $c = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $_.Id) -EA SilentlyContinue).CommandLine
    if (-not $c) { return }
    $keep = ($c -match 'issue49_integ012\\s11_agent_owned_' -and $c -match '--provider ollama')
    if (-not $keep) {
      W ("KILL_FOREIGN_DEEP2=" + $_.Id)
      Stop-Process -Id $_.Id -Force -EA SilentlyContinue
    }
  }
  Start-Sleep 4
}
W 'DONE'
exit 0
