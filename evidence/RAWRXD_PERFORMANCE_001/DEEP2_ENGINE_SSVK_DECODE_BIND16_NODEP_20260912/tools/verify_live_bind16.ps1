param([string]$Log = ".\bind16_live.log")
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Log)) { throw "Missing log: $Log" }
$text = Get-Content $Log -Raw
$forbidden = @(
  'STALE_72_BYTE_PATH_USED=1',
  'HOST_FORWARD_LAYER_CALLS=[1-9]',
  'HOST_MATERIALIZATIONS=[1-9]',
  'CPU_F32_EXPANDS=[1-9]',
  'DEVICE_LOST=1',
  'SEALED_LOGITS_REUSE=1'
)
foreach ($p in $forbidden) {
  if ($text -match $p) {
    Write-Host "BIND16_VERIFY=FAIL pattern=$p"
    exit 20
  }
}
$passes = [regex]::Matches($text, 'BATCH2_PRODUCT_DECODE_BIND=PASS').Count
if ($passes -lt 16) {
  Write-Host "BIND16_VERIFY=FAIL pass_tokens=$passes expected>=16"
  exit 21
}
if ($text -notmatch 'BIND16_WINDOW_AUTHORITY=1') {
  Write-Host "BIND16_VERIFY=FAIL missing BIND16_WINDOW_AUTHORITY=1"
  exit 22
}
Write-Host "BIND16_VERIFY=PASS pass_tokens=$passes"
Write-Host "LIVE_PRODUCT_RUN=PASS_IF_LOG_REAL"
Write-Host "PROMOTE=0"
