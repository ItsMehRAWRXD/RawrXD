param(
  [Parameter(Mandatory=$true)][string]$Receipt
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Receipt)) { throw "missing receipt: $Receipt" }
$kv = @{}
Get-Content $Receipt | ForEach-Object {
  if ($_ -match '^([^= ]+)=(.*)$') { $kv[$matches[1]] = $matches[2].Trim() }
}
$required = @(
  'GATE','STATUS','TARGET','GENERATED_TOKENS','RESIDENCY_SEALED','wup_d',
  'WEIGHT_BYTES_REQUESTED_TOTAL','WEIGHT_BYTES_ALREADY_LOCAL',
  'BYTES_NOT_ALREADY_LOCAL_TOTAL','BYTES_NOT_ALREADY_LOCAL_PER_TOKEN',
  'HOST_TO_DEVICE_BYTES','INTER_GPU_BYTES','CRITICAL_PATH_HOST_BYTES',
  'GPU0_FORWARD_COUNT','GPU1_FORWARD_COUNT','SAME_TOKEN_OVERLAP_COUNT',
  'GENERATION_WALL_NS','TOKEN_NS_P50','TOKEN_NS_P95','TPS_MEASURED_MILLI',
  'ROOFLINE_LOCALITY','CERT_EXIT','PROMOTE'
)
foreach ($k in $required) { if (!$kv.ContainsKey($k)) { throw "missing $k" } }
$ok = ($kv.GATE -eq 'DEEP2_ROOFLINE_LOCALITY_001') -and
      ($kv.STATUS -eq 'LIVE_PRODUCT_PASS') -and
      ($kv.TARGET -eq '64') -and ($kv.GENERATED_TOKENS -eq '64') -and
      ($kv.RESIDENCY_SEALED -eq '1') -and ($kv.wup_d -eq '0') -and
      ($kv.ROOFLINE_LOCALITY -eq 'PASS') -and ($kv.CERT_EXIT -eq '0') -and
      ($kv.PROMOTE -eq '0')
if (!$ok) {
  Write-Host 'VERIFY_ROOFLINE_LOCALITY=FAIL EXIT=2'
  exit 2
}
Write-Host 'VERIFY_ROOFLINE_LOCALITY=PASS EXIT=0'
exit 0
