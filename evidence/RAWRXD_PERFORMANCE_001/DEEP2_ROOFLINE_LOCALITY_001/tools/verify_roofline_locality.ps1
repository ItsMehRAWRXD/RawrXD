param(
  [string]$Log = ".\roofline_locality_live.log",
  [string]$Receipt = ".\RECEIPT.txt"
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Log)) { throw "Missing log: $Log" }
if (!(Test-Path $Receipt)) { throw "Missing receipt: $Receipt" }
$text = Get-Content $Log -Raw
$rec = Get-Content $Receipt -Raw
$forbidden = @(
  'SOLO_FALLBACK_USED=1',
  'DUALSTICK_RESET=1',
  'STALE_72_BYTE_PATH_USED=1'
)
foreach ($p in $forbidden) {
  if ($text -match $p) {
    Write-Host "ROOFLINE_VERIFY=FAIL pattern=$p"
    exit 20
  }
}
function Get-Rec([string]$name) {
  $m = [regex]::Match($rec, "(?m)^$name=(.+)$")
  if (-not $m.Success) { return $null }
  return $m.Groups[1].Value.Trim()
}
$tok = [uint64](Get-Rec 'GENERATED_TOKENS')
$wup = Get-Rec 'wup_d'
$bpt = Get-Rec 'BYTES_NOT_ALREADY_LOCAL_PER_TOKEN'
$rf = Get-Rec 'ROOFLINE_LOCALITY'
$g0 = [uint64](Get-Rec 'GPU0_FORWARD_COUNT')
$g1 = [uint64](Get-Rec 'GPU1_FORWARD_COUNT')
$ov = [uint64](Get-Rec 'SAME_TOKEN_OVERLAP_COUNT')
if ($tok -lt 64) {
  Write-Host "ROOFLINE_VERIFY=HOLD tokens=$tok expected>=64"
  exit 21
}
if ($wup -ne '0') {
  Write-Host "ROOFLINE_VERIFY=FAIL wup_d=$wup expected=0"
  exit 22
}
if ($g0 -le 0 -or $g1 -le 0) {
  Write-Host "ROOFLINE_VERIFY=HOLD dual_fwd g0=$g0 g1=$g1"
  exit 23
}
if ($ov -le 0) {
  Write-Host "ROOFLINE_VERIFY=HOLD overlap=$ov"
  exit 24
}
if ($rf -ne 'PASS') {
  Write-Host "ROOFLINE_VERIFY=HOLD ROOFLINE_LOCALITY=$rf bpt=$bpt"
  exit 25
}
Write-Host "ROOFLINE_VERIFY=PASS tokens=$tok wup_d=$wup bpt=$bpt overlap=$ov"
Write-Host "PROMOTE=0"
exit 0
