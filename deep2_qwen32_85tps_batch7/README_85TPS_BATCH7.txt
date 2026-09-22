Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 7: items 51–55
======================================================================

No Batch-6 receipt was supplied in this request, so this batch continues by
removing remaining warm-path host/materialization costs.

51  Resident dual-GPU batch input mirror
    - one activation upload per GPU per grouped QKV/Gate-Up operation
    - persistent device input buffer
    - reused by multiple resident Q4_K weights

52  Pinned row-slice weight residency
    - after first materialization, dense Q4_K row/column slices become pinned
    - LRU eviction skips pinned target weights
    - intended steady state: ZERO weight uploads after warmup

53  Resident grouped QKV / Gate-Up dispatch
    - QKV: one input upload + 3 resident Q4_K GEMVs per GPU
    - Gate/Up: one input upload + 2 resident Q4_K GEMVs per GPU
    - pinned weight slices

54  Async secondary slice return
    - secondary GPU output readback can be submitted before primary finishes
    - explicit DownloadTicket
    - no Vulkan peer-memory assumption

55  Authority v6
    - retains exact ordinary-greedy parity
    - retains GPU1 readiness requirement
    - retains 3 independent >=85 TPS steady runs
    - NEW: measured weight-upload delta must be ZERO on both GPUs
    - NEW: pinned weight entries/bytes must be nonzero on both GPUs

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch7.zip" `
  "F:\~dev\qwen32_85tps_batch7" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch7\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Rebuild
-------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run
---
$env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

Final fail-closed law
---------------------
SPEC_GREEDY_PARITY=PASS
GPU_DEVICES>=2
GPU1_DEVICE_READY=1
STRICT_VIOLATION=0
UNPLANNED_FALLBACKS=0

VERIFIED_PER_TARGET_PASS>1.0
GPU_TOP1_BATCHES>0
GPU_BATCH_NORM_OPS>0
GPU_BATCH_SWIGLU_OPS>0
GPU_BATCH_ATTENTION_OPS>0
DUAL_COLUMN_SPLIT_OPS>0
KV_MIRROR_RESIDENT_ATTN>0
PIPELINE_WINDOWS>0

SLOT0_WEIGHT_UPLOAD_DELTA_MEASURED=0
SLOT1_WEIGHT_UPLOAD_DELTA_MEASURED=0
SLOT0_PINNED_WEIGHT_ENTRIES>0
SLOT1_PINNED_WEIGHT_ENTRIES>0
ZERO_MEASURED_WEIGHT_UPLOADS=PASS

STEADY_RUN0_TPS>=85
STEADY_RUN1_TPS>=85
STEADY_RUN2_TPS>=85

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This is still source, not benchmark evidence. If GPU1 cannot create a Vulkan
device, or any measured run is below 85, authority remains HOLD.
