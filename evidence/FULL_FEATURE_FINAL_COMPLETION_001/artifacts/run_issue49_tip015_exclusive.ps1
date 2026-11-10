# Exclusive Issue #49 for tip_final_integ_015 (HOST_SEED opt-in OFF + 7B watchdog).
# tip_014 frozen for measured IDE fail + loop 08-11 authority. No blanket Native* kill under lock (wrapper cleans before lock waiters).
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$harness = Join-Path $root 'artifacts\issue49_integ015_remeasure.ps1'
$expect = 'F6A11C84D71C79B7B62832EEDD9271539BC310A0B8879C6E41E50AFFEB705E6D'
@(
  'OWNER=issue49_tip015_hostseed_optin_watchdog7b'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'HOST_SEED=OFF'
  'MODEL=qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
) | Set-Content -LiteralPath $lock -Encoding ASCII
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_AGENTIC_QUIET = '0'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_MAX_WALL_SEC = '7200'
$env:RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS = '300000'
$env:RAWRXD_AGENTIC_WATCHDOG_WALL_MS = '7200000'
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

