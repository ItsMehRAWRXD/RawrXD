# Exclusive Issue #49 tip_final_integ_017 (keepalive + orphan ledger wait).
# Anti-freeze: lock held; PID-scoped kills; no EnumWindows floods; AgentWait long for 7B.
$ErrorActionPreference = "Continue"
$root = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001"
$lock = Join-Path $root "artifacts\ISSUE49_EXCLUSIVE.lock"
$harness = Join-Path $root "artifacts\issue49_integ017_remeasure.ps1"
$shaFile = Join-Path $root "candidates\tip_final_integ_017\SHA256.txt"
$expect = if (Test-Path $shaFile) { (Get-Content $shaFile -Raw).Trim() } else { "UNSET" }
$logOut = Join-Path $root "artifacts\issue49_integ017\_exclusive_clean_remeasure.log"
$logErr = Join-Path $root "artifacts\issue49_integ017\_exclusive_clean_remeasure.err.log"
New-Item -ItemType Directory -Force -Path (Split-Path $logOut) | Out-Null
if (Test-Path -LiteralPath $lock) {
  $prev = Get-Content -LiteralPath $lock -Raw -EA SilentlyContinue
  Write-Host "LOCK_HELD aborting: $prev"
  exit 9
}
@(
  "OWNER=issue49_tip017_clean_exclusive_remeasure"
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  "DO_NOT_STOP_PROCESS_NATIVE_EXT=1"
  "HOST_SEED=OFF"
  "PREFILL_CHUNK=128"
  "KEEPALIVE=1"
  "ORPHAN_LOOP_WAIT=1"
  "NO_ENUMWINDOWS_FLOOD=1"
  "AGENT_WAIT_SEC=7200"
  "MODEL=qwen2.5-coder-7b-instruct.Q4_K_M.gguf"
) | Set-Content -LiteralPath $lock -Encoding ASCII

# Kill tip012/016/017 guardians only (command-line scoped).
Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
  $_.CommandLine -and ($_.CommandLine -match '_tip01[0-9]_guardian|ISSUE49.*guardian|watchdog_exclusive_tip012')
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }

# PID-scoped: stop competing IDE/loop/debuggee by image, and foreign freeze PIN if present.
foreach ($n in @('RawrXD-Win32IDE-Native-Ext','deep2_agentic_loop','debuggee_fixture','RXD_PIN_A190_35C22','RawrXD-FreezeSeal','RawrXD-FreezeGate')) {
  Get-Process -Name $n -EA SilentlyContinue | ForEach-Object {
    Write-Host "PID_SCOPED_KILL name=$n pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
}
Start-Sleep 2

$env:RAWRXD_FORCE_LOCAL_AGENTIC = "1"
$env:RAWRXD_AGENTIC_QUIET = "0"
$env:RAWRXD_GUI_APPROVE_MUTATIONS = "YES"
$env:RAWRXD_AGENTIC_MAX_WALL_SEC = "7200"
$env:RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS = "900000"
$env:RAWRXD_AGENTIC_WATCHDOG_WALL_MS = "7200000"
$env:RAWRXD_PREFILL_CHUNK = "128"
Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue

$code = 1
try {
  # Long enough for 7B prefill + TOOL path; stdout/err tee for orphan-wait proof.
  & $harness -AgentWaitSec 7200 -ModelPath "F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf" -ExpectSha $expect *>&1 |
    Tee-Object -FilePath $logOut
  $code = $LASTEXITCODE
} catch {
  $_ | Out-File -FilePath $logErr -Append
  $code = 1
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
}
exit $(if ($null -eq $code) { 1 } else { $code })
