# tip018 clean exclusive — GhostText→Ollama disabled during Deep2 7B PrefillBatch
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$art = Join-Path $root 'artifacts\issue49_integ018'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$harness = Join-Path $root 'artifacts\issue49_integ018_remeasure.ps1'
$iso = Join-Path $art 'exclusive_work_tip018'
$bug = Join-Path $iso 'bug.cpp'
$expect = (Get-Content (Join-Path $root 'candidates\tip_final_integ_018\SHA256.txt') -Raw).Trim()
$hb = Join-Path $art '_exclusive_heartbeat.txt'
$wrapLog = Join-Path $art '_exclusive_wrap.log'
function W([string]$m) {
  $l = "$(Get-Date -Format o) $m"
  Add-Content $wrapLog $l
  Write-Host $l
}

if (Test-Path $lock) {
  W "ABORT_LOCK_HELD $(Get-Content $lock -Raw)"
  exit 9
}
@(
  "OWNER=issue49_tip018_ghosttext_off_exclusive"
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  "HOST_SEED=OFF"
  "ORPHAN_LOOP_WAIT=1"
  "KEEPALIVE=1"
  "NO_ENUMWINDOWS_FLOOD=1"
  "AGENT_WAIT_SEC=7200"
  "GHOSTTEXT=DISABLED_FORCE_LOCAL_AGENTIC"
  "RAWRXD_DISABLE_GHOSTTEXT=1"
  "RAWRXD_DISABLE_GHOST_OLLAMA=1"
  "RAWRXD_GHOST_OLLAMA=0"
  "ISOLATED_FIXTURE=$bug"
) | Set-Content $lock -Encoding ASCII
W "LOCK_ACQUIRED"

Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
  $_.CommandLine -and ($_.CommandLine -match '_tip01[0-9]_guardian|watchdog_exclusive_tip012|ISSUE49.*guardian')
} | ForEach-Object {
  W "KILL_GUARDIAN $($_.ProcessId)"
  Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
}
foreach ($n in @('RawrXD-Win32IDE-Native-Ext','deep2_agentic_loop','debuggee_fixture','RXD_PIN_A190_35C22','RawrXD-FreezeSeal','RawrXD-FreezeGate')) {
  Get-Process -Name $n -EA SilentlyContinue | ForEach-Object {
    W "PID_KILL $n $($_.Id)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
}
Start-Sleep 2

$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_DISABLE_GHOSTTEXT = '1'
$env:RAWRXD_DISABLE_GHOST_OLLAMA = '1'
$env:RAWRXD_GHOST_OLLAMA = '0'
Remove-Item Env:RAWRXD_GHOST_DURING_AGENTIC -EA SilentlyContinue
$env:RAWRXD_AGENTIC_QUIET = '0'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_MAX_WALL_SEC = '7200'
$env:RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS = '900000'
$env:RAWRXD_AGENTIC_WATCHDOG_WALL_MS = '7200000'
$env:RAWRXD_PREFILL_CHUNK = '128'
$env:RAWRXD_ISSUE49_HEARTBEAT = $hb
Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
"boot $(Get-Date -Format o)" | Set-Content $hb -Encoding ASCII

$code = 1
try {
  W "HARNESS_START expect=$expect bug=$bug"
  & $harness -AgentWaitSec 7200 -ModelPath 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf' -ExpectSha $expect -ProjectCpp $bug
  $code = $LASTEXITCODE
  W "HARNESS_EXIT=$code"
} catch {
  W "HARNESS_THROW $($_.Exception.Message)"
  $code = 1
} finally {
  Remove-Item $lock -Force -EA SilentlyContinue
  W 'LOCK_RELEASED'
}
exit $(if ($null -eq $code) { 1 } else { $code })
