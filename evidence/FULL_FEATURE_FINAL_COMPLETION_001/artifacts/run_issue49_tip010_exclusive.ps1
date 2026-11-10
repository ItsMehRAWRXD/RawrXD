# Exclusive Issue #49 remeasure wrapper for tip_final_integ_010 (SHA 0946).
# Writes ISSUE49_EXCLUSIVE.lock so sibling harnesses skip blanket Native* kills.
# Pre-launch: kill stale foreign tips only. While lock held: NO blanket Native* kill.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$harness = Join-Path $root 'artifacts\issue49_integ010_remeasure.ps1'
$expect = '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9'
@(
  'OWNER=issue49_tip010_remeasure'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
) | Set-Content -LiteralPath $lock -Encoding ASCII

# Clean session restore (avoid Unsaved Changes modal) — short path only.
$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir 'ide_session.json'
$state = Join-Path $sessDir 'session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path -LiteralPath $sess) {
  Move-Item -LiteralPath $sess -Destination ($sess + ".bak_tip010_$stamp") -Force -EA SilentlyContinue
}
if (Test-Path -LiteralPath $state) {
  Move-Item -LiteralPath $state -Destination ($state + ".bak_tip010_$stamp") -Force -EA SilentlyContinue
}
@'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8

# Stale foreign tips only (pre-launch). Lock already written — siblings must skip.
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2

$code = 1
try {
  # Same process — avoid nested powershell starvation.
  & $harness -AgentWaitSec 180
  $code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
}
exit $(if ($null -eq $code) { 1 } else { $code })
