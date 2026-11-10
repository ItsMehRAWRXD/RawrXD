# Exclusive Debug+FourPanel for tip_final_integ_012 (SHA 6191E58E). PROMOTE=0. No tip-move.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$src = Join-Path $root 'artifacts\run_integ009_four_panel_reverify.ps1'
$tmp = Join-Path $root 'artifacts\_four_panel_body_012.ps1'
$expect = (Get-Content (Join-Path $root 'candidates\tip_final_integ_012\SHA256.txt') -Raw).Trim()
$tipDir = Join-Path $root 'candidates\tip_final_integ_012'
@(
  'OWNER=integ012_four_panel_exclusive'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'GATE=G5_DEBUG_G7_FOUR_PANEL_INTEG012'
) | Set-Content -LiteralPath $lock -Encoding ASCII

$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir 'ide_session.json'
$state = Join-Path $sessDir 'session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path -LiteralPath $sess) { Move-Item -LiteralPath $sess -Destination ($sess + ".bak_fp012_$stamp") -Force -EA SilentlyContinue }
if (Test-Path -LiteralPath $state) { Move-Item -LiteralPath $state -Destination ($state + ".bak_fp012_$stamp") -Force -EA SilentlyContinue }
Set-Content -LiteralPath $sess -Value '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}' -Encoding UTF8

cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2

$body = Get-Content -LiteralPath $src | Select-Object -Skip 5
$body = $body | ForEach-Object {
  $_ -replace 'tip_final_integ_009','tip_final_integ_012' `
     -replace '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9',$expect `
     -replace 'INTEG009_','INTEG012_'
}
$body | Set-Content -LiteralPath $tmp -Encoding UTF8

$code = 1
try {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $tmp
  $code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
  Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
}
Write-Host "FOUR_PANEL_EXIT=$code"
Get-Content (Join-Path $root 'artifacts\INTEG012_DEBUG_UI_HARNESS_RECEIPT.txt') -EA SilentlyContinue
exit $(if ($null -eq $code) { 1 } else { $code })
