# Exclusive Issue #49 product-final for tip_final_integ_011 (tool-wire).
# Does NOT overwrite tip_010. No blanket Native* kill while lock held.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$harness = Join-Path $root 'artifacts\issue49_integ011_remeasure.ps1'
$expect = '167A2CB972212F88997178B7C351AB07E2F30EA22A5AE321992DCC5C9D13DA86'
@(
  'OWNER=issue49_tip011_toolwire'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
) | Set-Content -LiteralPath $lock -Encoding ASCII
$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir 'ide_session.json'
$state = Join-Path $sessDir 'session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path -LiteralPath $sess) { Move-Item -LiteralPath $sess -Destination ($sess + ".bak_tip011_$stamp") -Force -EA SilentlyContinue }
if (Test-Path -LiteralPath $state) { Move-Item -LiteralPath $state -Destination ($state + ".bak_tip011_$stamp") -Force -EA SilentlyContinue }
@'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8
# Pre-launch stale kill only (lock already written).
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2
$code = 1
try {
  & $harness -AgentWaitSec 180
  $code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
}
exit $(if ($null -eq $code) { 1 } else { $code })


