# Resolve local packed-dual sources for BIND16 export (no subprocess).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$agg = Join-Path (Split-Path -Parent $root) 'DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001'
$live = Join-Path (Split-Path -Parent $root) 'DEEP2_DUAL_AGGREGATE_SSVK_BIND_001'
$mat = Join-Path (Split-Path -Parent $root) 'DEEP2_MATERIAL_DUAL_OVERLAP_NODEP_20260912'
$engine = Join-Path (Split-Path (Split-Path -Parent (Split-Path -Parent $root))) 'src\deep2'

$need = @(
  (Join-Path $live 'src\d2_live_vk.h'),
  (Join-Path $mat 'include\d2_material_overlap.h'),
  (Join-Path $engine 'Deep2SsVkPackedDualAdapter.cpp'),
  (Join-Path $engine 'd2_packed_q2k_product_run_v1.cpp')
)
foreach ($p in $need) {
  if (!(Test-Path $p)) {
    Write-Host "RESOLVE_PACKED_DUAL=FAIL missing=$p"
    exit 10
  }
}
Write-Host "RESOLVE_PACKED_DUAL=PASS"
Write-Host "IN_PROCESS=1"
Write-Host "CREATEPROCESS=FORBIDDEN"
Write-Host "PROMOTE=0"
