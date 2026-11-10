# Exclusive Debug+FourPanel remesure for tip_final_integ_009 (SHA 0946).
# Holds ISSUE49_EXCLUSIVE.lock; runs four_panel body without its early lock-exit.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$src = Join-Path $root 'artifacts\run_integ009_four_panel_reverify.ps1'
$tmp = Join-Path $root 'artifacts\_four_panel_body_009.ps1'
$expect = '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9'
@(
  'OWNER=integ009_four_panel_exclusive'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'GATE=G5_DEBUG_G7_FOUR_PANEL'
) | Set-Content -LiteralPath $lock -Encoding ASCII

$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir 'ide_session.json'
$state = Join-Path $sessDir 'session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path -LiteralPath $sess) {
  Move-Item -LiteralPath $sess -Destination ($sess + ".bak_fp009_$stamp") -Force -EA SilentlyContinue
}
if (Test-Path -LiteralPath $state) {
  Move-Item -LiteralPath $state -Destination ($state + ".bak_fp009_$stamp") -Force -EA SilentlyContinue
}
@'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8

cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2

# Skip lock gate (first 5 lines)
Get-Content -LiteralPath $src | Select-Object -Skip 5 | Set-Content -LiteralPath $tmp -Encoding UTF8

$code = 1
try {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $tmp
  $code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
}
Write-Host "FOUR_PANEL_EXIT=$code"
exit $(if ($null -eq $code) { 1 } else { $code })
