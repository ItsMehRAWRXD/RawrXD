$ownFile = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\step08_11_evidence\loop_pid_s11.txt"
$out = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\_tip016_guardian.out.txt"
"" | Set-Content $out
$deadline = (Get-Date).AddSeconds(2400)
while ((Get-Date) -lt $deadline) {
  $own = 0
  if (Test-Path $ownFile) { $t = Get-Content $ownFile -Raw; if ($t -match "OWN_PID=(\d+)") { $own = [int]$Matches[1] } }
  Get-CimInstance Win32_Process | Where-Object {
    ($_.CommandLine -match "tip_final_integ_016") -or (
      $_.Name -eq "deep2_agentic_loop.exe" -and $own -gt 0 -and $_.ProcessId -ne $own
    )
  } | ForEach-Object {
    Add-Content $out ("$(Get-Date -Format o) KILL=$($_.ProcessId) $($_.Name)")
    Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
  }
  if ($own -gt 0 -and -not (Get-Process -Id $own -EA SilentlyContinue)) {
    # owned tip012 dead and no relaunch requested here
    if (-not (Get-Process -Name deep2_agentic_loop -EA SilentlyContinue)) { Start-Sleep 30; if (-not (Get-Process -Name deep2_agentic_loop -EA SilentlyContinue)) { break } }
  }
  Start-Sleep 1
}
