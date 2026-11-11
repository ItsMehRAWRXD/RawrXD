# Exclusive OUTPUT HWND for tip_final_integ_011 (crash-fix SHA). PROMOTE=0. No tip-move.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$exe = Join-Path $root 'candidates\tip_final_integ_011\RawrXD-Win32IDE-Native-Ext.exe'
$expect = (Get-Content (Join-Path $root 'candidates\tip_final_integ_011\SHA256.txt') -Raw).Trim()
$outDir = Join-Path $root 'artifacts'
$logDir = Join-Path $root 'candidates\tip_final_integ_011\output_reverify_logs'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
@(
  'OWNER=integ011_output_exclusive'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'GATE=G4_OUTPUT_REVERIFY_INTEG011'
) | Set-Content -LiteralPath $lock -Encoding ASCII

$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir 'ide_session.json'
$state = Join-Path $sessDir 'session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path -LiteralPath $sess) { Move-Item -LiteralPath $sess -Destination ($sess + ".bak_out011_$stamp") -Force -EA SilentlyContinue }
if (Test-Path -LiteralPath $state) { Move-Item -LiteralPath $state -Destination ($state + ".bak_out011_$stamp") -Force -EA SilentlyContinue }
Set-Content -LiteralPath $sess -Value '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}' -Encoding UTF8

cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2

$pre = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
Write-Host "PRE_SHA=$pre"
Write-Host "SHA_MATCH=$([int]($pre -eq $expect))"
if ($pre -ne $expect) {
  Write-Host 'DISK_DRIFT=1'
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
  exit 3
}

Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue
$code = 1
try {
  & 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ea5d_output_problems_hwnd.ps1' `
    -TipExe $exe `
    -ExpectSha $expect `
    -BrokenCpp 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp' `
    -OutDir $outDir `
    -LogDir $logDir `
    -WaitSec 55
  $code = $LASTEXITCODE
} finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
}

$post = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
Write-Host "HARNESS_EXIT=$code"
Write-Host "POST_SHA=$post"
Write-Host "DISK_POST_DRIFT=$([int]($post -ne $expect))"
$src = Join-Path $outDir 'EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt'
$dst = Join-Path $outDir 'INTEG011_OUTPUT_HWND_HARNESS_RECEIPT.txt'
if (Test-Path $src) {
  Copy-Item $src $dst -Force
  Write-Host "COPIED=$dst"
  Get-Content $dst
}
exit $(if ($null -eq $code) { 1 } else { $code })
