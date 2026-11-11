# G4_OUTPUT_REVERIFY — tip_final_integ_007 only. PROMOTE=0. No tip-move.
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_007\RawrXD-Win32IDE-Native-Ext.exe'
$expect = 'ACBE6150D86ECF22A623DA180C78861AC3A91CAA14E761B4C65BB1E7A2C7BE07'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$logDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_007\output_reverify_logs'
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
$dst = Join-Path $outDir 'INTEG007_OUTPUT_HWND_HARNESS_RECEIPT.txt'
if (Test-Path $src) {
  Copy-Item $src $dst -Force
  Write-Host "COPIED=$dst"
  Get-Content $dst
}
$rl = Get-ChildItem $outDir -Filter 'ea5d_out_prob_hwnd_run_*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($rl) { Write-Host "RUNLOG=$($rl.FullName)" }
exit $exit
