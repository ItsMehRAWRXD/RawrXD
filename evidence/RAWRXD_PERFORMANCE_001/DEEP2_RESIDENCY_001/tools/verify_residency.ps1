param([string]$Log = ".\residency_live.log")
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Log)) { throw "Missing log: $Log" }
$text = Get-Content $Log -Raw
$forbidden = @(
  'SOLO_FALLBACK_USED=1',
  'DUALSTICK_RESET=1',
  'STALE_72_BYTE_PATH_USED=1'
)
foreach ($p in $forbidden) {
  if ($text -match $p) {
    Write-Host "RESIDENCY_VERIFY=FAIL pattern=$p"
    exit 20
  }
}
$rt = [regex]::Matches($text, 'RESIDENCY_TOKEN').Count
$pd = [regex]::Matches($text, 'PERSISTENT_DECODE_TOKEN').Count
$passes = [regex]::Matches($text, 'BATCH2_PRODUCT_DECODE_BIND=PASS').Count
if ($rt -lt 16) {
  Write-Host "RESIDENCY_VERIFY=HOLD residency_tokens=$rt expected>=16"
  exit 21
}
if ($passes -lt 16) {
  Write-Host "RESIDENCY_VERIFY=HOLD bind_pass=$passes expected>=16"
  exit 22
}
if ($text -notmatch 'BIND16_WINDOW_AUTHORITY=1') {
  Write-Host "RESIDENCY_VERIFY=HOLD missing BIND16_WINDOW_AUTHORITY=1"
  exit 23
}
# Per-token flatness after first RESIDENCY_TOKEN (warm allowed on t=first)
$lines = [regex]::Matches($text, 'RESIDENCY_TOKEN[^\r\n]+')
if ($lines.Count -lt 2) {
  Write-Host "RESIDENCY_VERIFY=HOLD need>=2 RESIDENCY_TOKEN lines"
  exit 24
}
function Get-Field([string]$line, [string]$name) {
  $m = [regex]::Match($line, "$name=(\d+)")
  if (-not $m.Success) { return $null }
  return [uint64]$m.Groups[1].Value
}
$base = $lines[0].Value
$w0 = Get-Field $base 'weight_up'
$m0 = Get-Field $base 'model_load'
$d0 = Get-Field $base 'dev_create'
$r0 = Get-Field $base 'reload_B'
$e0 = Get-Field $base 'pin_evict'
$res0 = Get-Field $base 'res_B'
for ($i = 1; $i -lt $lines.Count; $i++) {
  $L = $lines[$i].Value
  $w = Get-Field $L 'weight_up'
  $m = Get-Field $L 'model_load'
  $d = Get-Field $L 'dev_create'
  $r = Get-Field $L 'reload_B'
  $e = Get-Field $L 'pin_evict'
  if ($w -ne $w0 -or $m -ne $m0 -or $d -ne $d0 -or $r -ne $r0 -or $e -ne $e0) {
    Write-Host "RESIDENCY_VERIFY=FAIL per_token_delta at line=$i w=$w/$w0 m=$m/$m0 d=$d/$d0 r=$r/$r0 e=$e/$e0"
    exit 25
  }
}
if ($null -eq $res0 -or $res0 -le 0) {
  Write-Host "RESIDENCY_VERIFY=HOLD resident_bytes=$res0"
  exit 26
}
Write-Host "RESIDENCY_VERIFY=PASS residency_tokens=$rt bind_pass=$passes persistent_tokens=$pd res_B=$res0"
Write-Host "PROMOTE=0"
exit 0
