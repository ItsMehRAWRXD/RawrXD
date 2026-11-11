$ErrorActionPreference = 'Continue'
$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if (Test-Path -LiteralPath $__i49lock) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present — not killing Native-Ext / not launching'
  exit 0
}
$e6cf = 'E6CF5BD2B23638B046926F301997926BD35B1524CD3D58B59A75A24946466A3E'
$tip = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008\RawrXD-Win32IDE-Native-Ext.exe'
$src = 'F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe'
$loopSrcCandidates = @(
  'F:\rawrxd\build_tip_ext_host_001\bin\deep2_agentic_loop.exe',
  'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008\deep2_agentic_loop.exe'
)

Write-Host "PREFLIGHT_TIP_EXISTS=$([IO.File]::Exists($tip))"
Write-Host "PREFLIGHT_SRC_EXISTS=$([IO.File]::Exists($src))"
$tipSha = if ([IO.File]::Exists($tip)) { (Get-FileHash -LiteralPath $tip -Algorithm SHA256).Hash } else { '' }
$srcSha = if ([IO.File]::Exists($src)) { (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash } else { '' }
Write-Host "TIP_SHA=$tipSha"
Write-Host "SRC_SHA=$srcSha"
$restored = 0
if ($tipSha -ne $e6cf) {
  if ($srcSha -ne $e6cf) { throw "RESTORE_BLOCKED src!=E6CF tip!=E6CF" }
  New-Item -ItemType Directory -Force -Path (Split-Path $tip) | Out-Null
  Copy-Item -LiteralPath $src -Destination $tip -Force
  $tipSha = (Get-FileHash -LiteralPath $tip -Algorithm SHA256).Hash
  $restored = 1
  Write-Host "RESTORED=1 TIP_SHA=$tipSha"
} else {
  Write-Host "RESTORE=HELD tip already E6CF"
}
if ($tipSha -ne $e6cf) { throw "POST_RESTORE_SHA_MISMATCH" }

$loopBeside = Join-Path (Split-Path $tip) 'deep2_agentic_loop.exe'
if (-not [IO.File]::Exists($loopBeside)) {
  foreach ($c in $loopSrcCandidates) {
    if ([IO.File]::Exists($c) -and $c -ne $loopBeside) {
      Copy-Item -LiteralPath $c -Destination $loopBeside -Force
      Write-Host "LOOP_STAGED_FROM=$c"
      break
    }
  }
}
Write-Host "LOOP_BESIDE=$([IO.File]::Exists($loopBeside))"

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','debuggee_fixture' -EA SilentlyContinue |
  Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

$harness = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_product_final_e6cf_chatfix.ps1'
$console = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ008_chatfix\harness_console.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $console) | Out-Null
Write-Host "RUN_HARNESS=$harness"
& powershell -NoProfile -ExecutionPolicy Bypass -File $harness *>&1 |
  Tee-Object -FilePath $console
$code = $LASTEXITCODE
Write-Host "HARNESS_EXIT=$code"
Write-Host "RESTORED=$restored"
Write-Host "FINAL_TIP_SHA=$((Get-FileHash -LiteralPath $tip -Algorithm SHA256).Hash)"
exit $code