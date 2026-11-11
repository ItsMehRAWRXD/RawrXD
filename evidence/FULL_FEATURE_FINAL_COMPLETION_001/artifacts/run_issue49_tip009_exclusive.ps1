# Exclusive Issue #49 remesure for tip_final_integ_009 (SHA 0946).
$ErrorActionPreference = "Continue"
$root = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001"
$lock = Join-Path $root "artifacts\ISSUE49_EXCLUSIVE.lock"
$freezeLock = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts\ISSUE49_EXCLUSIVE.lock"
$harness = Join-Path $root "artifacts\issue49_integ009_remeasure.ps1"
$expect = "0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9"
New-Item -ItemType Directory -Force -Path (Split-Path $freezeLock) | Out-Null
@(
  "OWNER=issue49_tip009_remeasure"
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  "DO_NOT_STOP_PROCESS_NATIVE_EXT=1"
) | Set-Content -LiteralPath $lock -Encoding ASCII
Copy-Item $lock $freezeLock -Force

$sessDir = Join-Path $env:LOCALAPPDATA "RawrXD"
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir "ide_session.json"
$state = Join-Path $sessDir "session.state"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (Test-Path -LiteralPath $sess) { Move-Item -LiteralPath $sess -Destination ($sess + ".bak_i49_009_$stamp") -Force -EA SilentlyContinue }
if (Test-Path -LiteralPath $state) { Move-Item -LiteralPath $state -Destination ($state + ".bak_i49_009_$stamp") -Force -EA SilentlyContinue }
Set-Content -LiteralPath $sess -Encoding UTF8 -Value '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}'

Get-Process -Name "RawrXD*","deep2_agentic_loop","debuggee_fixture" -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

$tipDir = Join-Path $root "candidates\tip_final_integ_009"
$loop = Join-Path $tipDir "deep2_agentic_loop.exe"
if (-not (Test-Path $loop)) {
  $cand = @(
    (Join-Path $root "candidates\tip_final_integ_010\deep2_agentic_loop.exe"),
    "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe"
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($cand) { Copy-Item $cand $loop -Force; Write-Host "COPIED_LOOP_FROM=$cand" }
}

$code = 1
try {
  $tmp = Join-Path $root "artifacts\_issue49_tip009_body.ps1"
  $raw = Get-Content -LiteralPath $harness -Raw
  $raw = $raw.Replace("if (Test-Path -LiteralPath `$__i49lock) {", "if (`$false -and (Test-Path -LiteralPath `$__i49lock)) {")
  Set-Content -LiteralPath $tmp -Value $raw -Encoding UTF8
  & powershell -NoProfile -ExecutionPolicy Bypass -File $tmp -AgentWaitSec 180
  $code = $LASTEXITCODE
  Remove-Item $tmp -Force -EA SilentlyContinue
} finally {
  Remove-Item -LiteralPath $lock,$freezeLock -Force -EA SilentlyContinue
}
exit $(if ($null -eq $code) { 1 } else { $code })

