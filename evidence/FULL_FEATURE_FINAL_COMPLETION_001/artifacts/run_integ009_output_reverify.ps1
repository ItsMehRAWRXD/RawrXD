# G4_OUTPUT_REVERIFY — tip_final_integ_009 / 0946 only. PROMOTE=0. No tip-move.
$ErrorActionPreference = 'Continue'
$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if (Test-Path -LiteralPath $__i49lock) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present — not killing Native-Ext / not launching'
  exit 0
}
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_009\RawrXD-Win32IDE-Native-Ext.exe'
$expect = '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$logDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_009\output_reverify_logs'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null

$pre = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
Write-Host "PRE_SHA=$pre"
Write-Host "SHA_MATCH=$([int]($pre -eq $expect))"
if ($pre -ne $expect) {
  Write-Host 'DISK_DRIFT=1'
  exit 3
}

Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

& 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ea5d_output_problems_hwnd.ps1' `
  -TipExe $exe `
  -ExpectSha $expect `
  -BrokenCpp 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp' `
  -OutDir $outDir `
  -LogDir $logDir `
  -WaitSec 55
$exit = $LASTEXITCODE

$post = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
Write-Host "HARNESS_EXIT=$exit"
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
exit $exit
