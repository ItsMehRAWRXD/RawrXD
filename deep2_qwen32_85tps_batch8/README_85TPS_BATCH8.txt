Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 8: items 56–60
======================================================================

No Batch-7 measured receipt accompanied this request. Batch 8 therefore targets
generic remaining hot-path overhead without weakening any existing authority.

56  Resident dual-GPU grouped outputs
    - persistent device buffers for 2/3 grouped matrix outputs
    - no per-weight output-buffer allocation in QKV / Gate-Up groups

57  One group return / merge
    - one contiguous mapped return slab per GPU for QKV or Gate-Up
    - removes individual matrix readback staging from grouped execution

58  Immutable dispatch-plan cache
    - caches row split and GpuWeightView geometry per immutable GGUF matrix
    - avoids repeated plan construction
    - intentionally does NOT pretend VkCommandBuffer execution is immutable

59  Direct speculative KV device-tail append
    - copies new K/V directly from token-major device buffers into persistent
      head-major device KV mirror
    - removes host materialization for the speculative tail when resident path
      is active
    - host KV remains correctness authority

60  Authority v7 hot-path budget
    - retains all prior PASS requirements
    - measured weight upload delta remains exactly zero
    - grouped output buffers cannot reallocate after warmup
    - records queue submits / verified token
    - records batch-input uploads / verified token
    - records direct device-KV append count

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch8.zip" `
  "F:\~dev\qwen32_85tps_batch8" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch8\*.patch" |
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

Fail-closed law
---------------
All prior requirements remain, including:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85

New:
  GROUP_OUTPUT_REALLOC_DELTA_SLOT0=0
  GROUP_OUTPUT_REALLOC_DELTA_SLOT1=0
  HOTPATH_OVERHEAD_BOUNDED=PASS

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This is a source drop, not performance evidence. Compile it, then use the
receipt to choose whether the remaining limiter is queue overhead, acceptance,
GPU1 readiness, target bandwidth, or attention/KV work.
