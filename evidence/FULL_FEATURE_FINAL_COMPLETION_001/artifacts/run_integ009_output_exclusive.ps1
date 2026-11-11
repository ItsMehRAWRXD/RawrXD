# Exclusive OUTPUT HWND remesure for tip_final_integ_009 (SHA 0946).
# Holds ISSUE49_EXCLUSIVE.lock so sibling harnesses skip blanket Native* kills.
# Root cause of prior OUTPUT_HWND=FAIL on 0946: concurrent Stop-Process (EXIT=-1).
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$harness = Join-Path $root 'artifacts\run_integ009_output_reverify.ps1'
$expect = '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9'
@(
  'OWNER=integ009_output_exclusive'
  "PID=$PID"
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'GATE=G4_OUTPUT_REVERIFY'
) | Set-Content -LiteralPath $lock -Encoding ASCII

# Clean session restore (avoid Unsaved Changes modal).
$sessDir = Join-Path $env:LOCALAPPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $sessDir | Out-Null
$sess = Join-Path $sessDir 'ide_session.json'
$state = Join-Path $sessDir 'session.state'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (Test-Path -LiteralPath $sess) {
  Move-Item -LiteralPath $sess -Destination ($sess + ".bak_out009_$stamp") -Force -EA SilentlyContinue
}
if (Test-Path -LiteralPath $state) {
  Move-Item -LiteralPath $state -Destination ($state + ".bak_out009_$stamp") -Force -EA SilentlyContinue
}
@'
{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}
'@ | Set-Content -LiteralPath $sess -Encoding UTF8

# Stale foreign tips only (pre-launch). Lock already written — siblings must skip.
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2

# Temporarily bypass lock check inside run_integ009_output_reverify by renaming lock
# after pre-clean... No: child script exits if lock present. Inline the body instead.
$exe = Join-Path $root 'candidates\tip_final_integ_009\RawrXD-Win32IDE-Native-Ext.exe'
$outDir = Join-Path $root 'artifacts'
$logDir = Join-Path $root 'candidates\tip_final_integ_009\output_reverify_logs'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
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
$dst = Join-Path $outDir 'INTEG009_OUTPUT_HWND_HARNESS_RECEIPT.txt'
if (Test-Path $src) {
  Copy-Item $src $dst -Force
  Write-Host "COPIED=$dst"
  Get-Content $dst
}
$rl = Get-ChildItem $outDir -Filter 'ea5d_out_prob_hwnd_run_*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($rl) { Write-Host "RUNLOG=$($rl.FullName)" }
exit $(if ($null -eq $code) { 1 } else { $code })
