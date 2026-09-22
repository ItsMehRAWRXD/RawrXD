Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 12: items 76–80
======================================================================

No Batch-11 measured receipt accompanied this request. Batch 12 targets the
remaining dual-GPU synchronization wall without weakening any prior gate.

76  Nonblocking resident Q4_K submit tickets
    - submit compute on each GPU without immediate wait
    - reusable ticket carries fence/timing/weight bytes
    - explicit wait only at dependency boundary

77  Persistent secondary transfer ring
    - three persistent host-visible mapped staging buffers
    - no recurring staging allocation/map/unmap
    - producer rotates slots
    - consumer waits only on selected slot

78  Async dual-GPU row-split path
    - GPU0 + GPU1 arithmetic submitted back-to-back
    - waits occur after both are in flight
    - GPU1 result then enters persistent transfer ring
    - measures async arithmetic overlap and wall duration

79  Overlap-driven row-split controller
    - bounded +/-5% adjustment per sample
    - actual completion time drives future row ownership
    - split changes only between token windows
    - can disable with DEEP2_ASYNC_SPLIT_CONTROL=0

80  Authority v11
    - every previous correctness/performance predicate remains
    - requires nonblocking Q4_K submits on BOTH GPUs
    - requires persistent GPU1 transfer-ring activity
    - reports async wait/ring wait
    - still requires three independent >=85 verified TPS runs

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch12.zip" `
  "F:\~dev\qwen32_85tps_batch12" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch12\*.patch" |
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
$env:DEEP2_ASYNC_SPLIT_CONTROL="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"
$env:DEEP2_Q4K_AUTOTUNE="1"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

New authority fields
--------------------
GPU0_Q4K_ASYNC_SUBMITS_DELTA>0
GPU1_Q4K_ASYNC_SUBMITS_DELTA>0
GPU1_DOWNLOAD_RING_SUBMITS_DELTA>0
ASYNC_DUAL_GPU_PATH=PASS

All earlier requirements remain, including:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  HOST_TRAFFIC_BOUNDED=PASS
  Q4K_AUTOTUNE=PASS
  RECORDED_Q4K_HOTPATH=PASS
  COST_DRIVEN_SPEC_WINDOW=PASS
  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This archive is source only. It is not an 85-TPS receipt until compiled and
the measured fail-closed authority executable returns PASS.
