# Exclusive Issue #49 tip_final_integ_016 (prefill-chunk 128 + ESP progress + flight 180s).
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$harness = Join-Path $root 'artifacts\issue49_integ016_remeasure.ps1'
$expect = '5A3577543CE4A1CBD17C610B76C4A2894731347D5B756DFEDB8413EE16FFEE18'
@(
  'OWNER=issue49_tip016_snap_noprogress_prefill_fix'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'HOST_SEED=OFF'
  'PREFILL_CHUNK=128'
  'MODEL=qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
) | Set-Content -LiteralPath $lock -Encoding ASCII
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_AGENTIC_QUIET = '0'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_MAX_WALL_SEC = '7200'
$env:RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS = '300000'
$env:RAWRXD_AGENTIC_WATCHDOG_WALL_MS = '7200000'
$env:RAWRXD_PREFILL_CHUNK = '128'
Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2
$code = 1
try {
  & $harness -AgentWaitSec 7200 -ModelPath 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf' -ExpectSha $expect
  $code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
}
exit $(if ($null -eq $code) { 1 } else { $code })

