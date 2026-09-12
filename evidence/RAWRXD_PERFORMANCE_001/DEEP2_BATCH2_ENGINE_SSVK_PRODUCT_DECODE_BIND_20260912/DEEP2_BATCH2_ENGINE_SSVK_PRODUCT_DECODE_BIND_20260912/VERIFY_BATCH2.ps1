param(
  [string]$Log = ".\batch2_live.log"
)

$ErrorActionPreference = 'Stop'
if (!(Test-Path $Log)) { throw "Missing log: $Log" }

$text = Get-Content $Log -Raw

$forbidden = @(
  'SEALED_LOGITS_REUSE=1',
  'HOST_FORWARD_LAYER_CALLS=[1-9]',
  'HOST_MATERIALIZATIONS=[1-9]',
  'CPU_F32_EXPANDS=[1-9]',
  'CRITICAL_PATH_NVME_READS=[1-9]',
  'EXTERNAL_RUNTIME_CALLS=[1-9]',
  'DEVICE_LOST=1',
  'STALE_72_BYTE_PATH_USED=1'
)

foreach ($p in $forbidden) {
  if ($text -match $p) {
    Write-Host "BATCH2_VERIFY=FAIL pattern=$p"
    exit 20
  }
}

$passes = [regex]::Matches($text, 'BATCH2_PRODUCT_DECODE_BIND=PASS').Count
if ($passes -lt 16) {
  Write-Host "BATCH2_VERIFY=FAIL pass_tokens=$passes expected>=16"
  exit 21
}

Write-Host "BATCH2_VERIFY=PASS pass_tokens=$passes"
Write-Host "PROMOTE=0"
