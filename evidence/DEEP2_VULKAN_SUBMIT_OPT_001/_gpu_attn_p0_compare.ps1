$ErrorActionPreference = 'Continue'
$evid = 'G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001'
$aLog = Join-Path $evid 'ab_A_shared_softmax.log'
$bLog = Join-Path $evid 'ab_B_shared_softmax.log'
function Get-GenStream([string]$path) {
  $line = Select-String -Path $path -Pattern 'GENSTREAM' | Select-Object -Last 1
  if (-not $line) { return @() }
  # expect token ids after GENSTREAM
  $m = [regex]::Match($line.Line, 'GENSTREAM[^\d]*([\d\s]+)')
  if (-not $m.Success) {
    $nums = [regex]::Matches($line.Line, '\b\d+\b') | ForEach-Object { [int]$_.Value }
    return @($nums)
  }
  return @($m.Groups[1].Value.Trim() -split '\s+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
}
function Get-Metric([string]$path, [string]$name) {
  $line = Select-String -Path $path -Pattern $name | Select-Object -Last 1
  if (-not $line) { return 'MISSING' }
  $m = [regex]::Match($line.Line, "$name[=:\s]+([0-9.eE+-]+)")
  if ($m.Success) { return $m.Groups[1].Value }
  return $line.Line.Trim()
}
$aTok = @(Get-GenStream $aLog)
$bTok = @(Get-GenStream $bLog)
$divIdx = -1
$maxN = [Math]::Min($aTok.Count, $bTok.Count)
for ($i = 0; $i -lt $maxN; $i++) {
  if ($aTok[$i] -ne $bTok[$i]) { $divIdx = $i; break }
}
if ($aTok.Count -ne $bTok.Count -and $divIdx -lt 0) { $divIdx = $maxN }
$parity = if ($divIdx -lt 0 -and $aTok.Count -gt 0 -and $aTok.Count -eq $bTok.Count) { 'PASS' } else { 'FAIL' }
$aTps = Get-Metric $aLog 'DECODE_TPS'
$bTps = Get-Metric $bLog 'DECODE_TPS'
$aSub = Get-Metric $aLog 'decode_submits_per_fwd'
if ($aSub -eq 'MISSING') { $aSub = Get-Metric $aLog 'submits_per_fwd' }
$bSub = Get-Metric $bLog 'decode_submits_per_fwd'
if ($bSub -eq 'MISSING') { $bSub = Get-Metric $bLog 'submits_per_fwd' }
$opt = Get-Content (Join-Path $evid 'BENCH_SHA256_OPTIMIZED.txt') -Raw
$optHash = if ($opt -match 'OPTIMIZED_SHA256=([A-F0-9]+)') { $Matches[1] } else { 'UNKNOWN' }
$asof = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
$submitLe10 = 'UNPROVEN'
if ($bSub -match '^[0-9.]+$') {
  $submitLe10 = if ([double]$bSub -le 10) { 'PASS' } else { "UNPROVEN (actual=$bSub)" }
}
@"
DEEP2_VULKAN_GPU_ATTN_001 / SUBMIT_OPT_001 ISOLATED_AB
ASOF=$asof
HOOK_REPAIR_001=PASS
BASELINE_SHA256=SEALED
OPTIMIZED_SHA256=$optHash
GPU_ATTN_DECODE=LIVE_WITH_HOST_UPLOAD
GPU_RESIDUAL_SILU=PENDING
HOST_FENCE_REDUCTION=PENDING
CB_CONTINUITY=HOLD
GPU_RESIDENT_ATTENTION=FALSE
SUBMIT_COUNT_LE_10=$submitLe10
TOKEN_PARITY=$parity$(if ($parity -eq 'FAIL') { " diverge_idx=$divIdx A=$($aTok[$divIdx]) B=$($bTok[$divIdx])" } else { '' })
LOGIT_PARITY=NOT_MEASURED
ARM_A_DECODE_TPS=$aTps
ARM_A_decode_submits_per_fwd=$aSub
ARM_B_DECODE_TPS=$bTps
ARM_B_decode_submits_per_fwd=$bSub
ARM_A_GENSTREAM=$($aTok -join ' ')
ARM_B_GENSTREAM=$($bTok -join ' ')
ISOLATED_AB=RAN
PROMOTE=0
OPTIMIZATION_COMPLETE=0
NOTE=AttnDecode still HOST uploads Q/KV after QKV fence; does NOT eliminate per-layer attention host dependency.
"@ | Set-Content -Path (Join-Path $evid 'ISOLATED_AB.txt') -Encoding utf8

if ($parity -eq 'FAIL') {
  @"
FIRST_DIVERGENCE
diverge_idx=$divIdx
A_tok=$($aTok[$divIdx])
B_tok=$($bTok[$divIdx])
ASOF=$asof
STATUS=TOKEN_PARITY_FAIL — parity-dump re-run may follow
CLASSIFICATION=PENDING_PARITY_DUMP
PROMOTE=0
"@ | Set-Content -Path (Join-Path $evid 'FIRST_DIVERGENCE.txt') -Encoding utf8
}

@"
DEEP2_VULKAN_SUBMIT_OPT_001 / DEEP2_VULKAN_GPU_ATTN_001 STATUS
ASOF=$asof
BASELINE_SEALED=1
BASELINE_SHA256=B7CEAEEF675EB86023FF15EA1DB045B5C58634543EB7DD86A1F3E6680D4B0750
OPTIMIZED_SHA256=$optHash
TOKEN_PARITY=$parity
LOGIT_PARITY=NOT_MEASURED
ARM_A_DECODE_TPS=$aTps ARM_A_SUBMITS=$aSub
ARM_B_DECODE_TPS=$bTps ARM_B_SUBMITS=$bSub
GPU_ATTN_DECODE=LIVE_WITH_HOST_UPLOAD
GPU_RESIDUAL_SILU=PENDING
HOST_FENCE_REDUCTION=PENDING
CB_CONTINUITY=HOLD
SUBMIT_COUNT_LE_10=$submitLe10
ISOLATED_AB=RAN
CODE_CHANGE_COMPLETE=0
OPTIMIZATION_COMPLETE=0
PROMOTE=0
SEE=ISOLATED_AB.txt BENCH_SHA256_OPTIMIZED.txt CONTRACT_DEEP2_VULKAN_GPU_ATTN_001.txt
"@ | Set-Content -Path (Join-Path $evid 'STATUS.txt') -Encoding utf8

@"
CONTRACT_DEEP2_VULKAN_GPU_ATTN_001
ASOF=$asof
SCOPE=shared-softmax AttnDecode token parity vs host; no CB continuity / host-staging in this contract.
HOOK_REPAIR_001=PASS
BASELINE_SHA256=SEALED
OPTIMIZED_SHA256=$optHash
GPU_ATTN_DECODE=LIVE_WITH_HOST_UPLOAD
GPU_RESIDENT_ATTENTION=FALSE
GPU_RESIDUAL_SILU=PENDING
HOST_FENCE_REDUCTION=PENDING
CB_CONTINUITY=HOLD
SUBMIT_COUNT_LE_10=$submitLe10
TOKEN_PARITY=$parity
LOGIT_PARITY=NOT_MEASURED
ISOLATED_AB=RAN
PROMOTE=0
OPTIMIZATION_COMPLETE=0
NEXT_GAP=if TOKEN_PARITY FAIL: DEEP2_ATTN_PARITY_DUMP diagnose; if PASS: CB continuity + residual/SiLU still required for submit reduction
"@ | Set-Content -Path (Join-Path $evid 'CONTRACT_DEEP2_VULKAN_GPU_ATTN_001.txt') -Encoding utf8

Write-Host "TOKEN_PARITY=$parity div=$divIdx"
Write-Host "A_TPS=$aTps A_SUB=$aSub B_TPS=$bTps B_SUB=$bSub"
