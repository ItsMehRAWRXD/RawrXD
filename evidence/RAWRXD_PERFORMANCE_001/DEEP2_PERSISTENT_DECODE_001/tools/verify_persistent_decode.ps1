param([string]$Log = ".\persistent_decode_live.log")
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Log)) { throw "Missing log: $Log" }
$text = Get-Content $Log -Raw
$forbidden = @(
  'SEALED_LOGITS_REUSE=1',
  'SOLO_FALLBACK_USED=1',
  'DUALSTICK_RESET=1',
  'STALE_72_BYTE_PATH_USED=1'
)
foreach ($p in $forbidden) {
  if ($text -match $p) {
    Write-Host "PERSISTENT_VERIFY=FAIL pattern=$p"
    exit 20
  }
}
$pd = [regex]::Matches($text, 'PERSISTENT_DECODE_TOKEN').Count
$passes = [regex]::Matches($text, 'BATCH2_PRODUCT_DECODE_BIND=PASS').Count
if ($pd -lt 16) {
  Write-Host "PERSISTENT_VERIFY=HOLD persistent_tokens=$pd expected>=16"
  exit 21
}
if ($passes -lt 16) {
  Write-Host "PERSISTENT_VERIFY=HOLD bind_pass=$passes expected>=16"
  exit 22
}
if ($text -notmatch 'BIND16_WINDOW_AUTHORITY=1') {
  Write-Host "PERSISTENT_VERIFY=HOLD missing BIND16_WINDOW_AUTHORITY=1"
  exit 23
}
$badSeal = [regex]::Matches($text, 'sealed=1').Count
if ($badSeal -gt 0) {
  Write-Host "PERSISTENT_VERIFY=FAIL sealed_logits_reuse_in_tokens=$badSeal"
  exit 24
}
Write-Host "PERSISTENT_VERIFY=PASS persistent_tokens=$pd bind_pass=$passes"
Write-Host "PROMOTE=0"
exit 0
