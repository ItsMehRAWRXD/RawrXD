Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 4: items 36–40
======================================================================

Purpose
-------
Batch 3 improved proposal quality and removed full-vocab logit readback.
Batch 4 attacks the remaining host-heavy verifier stages.

36  GPU speculative batch RMSNorm + SwiGLU
    - 1..4 verification tokens
    - subgroup RMS reduction
    - same Vulkan backend, no external library

37  GPU causal speculative attention
    - exact GQA visibility: candidate b sees committed KV + candidates <= b
    - host KV remains authority
    - active layer KV packed once per verification window

38  Q4_K dual-GPU column-split batch projection
    - intended for O projection and FFN wDown
    - split only on legal 256-element Q4_K K-block boundaries
    - each card computes a full-output partial
    - partial vectors are summed exactly

39  Bind Batch-4 GPU primitives into forwardSpeculativeBlock
    - batch attention norm
    - batch causal attention
    - column-split O
    - batch FFN norm/SwiGLU
    - column-split down

40  Authority v3
    Final PASS now requires proof that all Batch-4 GPU structures actually ran.

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch4.zip" `
  "F:\~dev\qwen32_85tps_batch4" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch4\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Rebuild shaders
---------------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

Build
-----
cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run
---
$env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 128

Final authority
---------------
SPEC_GREEDY_PARITY=PASS
GPU_DEVICES=2
STRICT_VIOLATION=0
UNPLANNED_FALLBACKS=0
GPU_TOP1_BATCHES>0
GPU_BATCH_NORM_OPS>0
GPU_BATCH_SWIGLU_OPS>0
GPU_BATCH_ATTENTION_OPS>0
DUAL_COLUMN_SPLIT_OPS>0
VERIFIED_PER_TARGET_PASS>1.0
DECODE_TPS_REAL_VERIFIED>=85.0
DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

No 85-TPS PASS is implied by applying this source. The executable must measure
>=85 verified output TPS and retain exact ordinary-greedy token parity.

If Batch 4 remains HOLD, Batch 5 should be driven by the receipt:
- if acceptance is low: draft quality/depth scheduling
- if verifier GPU time dominates: persistent device KV mirror + keep the whole
  4-token activation chain resident on R9700 between QKV/O/FFN operations
- if dual column split stalls: tune split ratio from measured per-card partial
  completion time rather than static throughput weights.
