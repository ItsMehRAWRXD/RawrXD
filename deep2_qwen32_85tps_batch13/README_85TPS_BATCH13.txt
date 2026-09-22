Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 13: items 81–85
======================================================================

No Batch-12 measured receipt accompanied this request. Batch 13 attacks queue
serialization and recurring secondary-transfer overhead.

81  Vulkan asynchronous transfer-queue discovery
    Preference:
      transfer-only family
      second queue in compute family
      same compute queue fallback
    Correctness never requires a separate queue.

82  Persistent transfer-queue ring
    - transfer command buffers allocated once per ring slot
    - staging stays persistently mapped
    - transfer queue used when available
    - no hot-path allocation/map/unmap

83  Dual-GPU fence fan-in
    - both GPU compute tickets already in flight before fan-in
    - fence status polling allows host scheduling work before dependency wait
    - measures GPU0/GPU1 duration, wall and arithmetic overlap

84  Three-stage speculative scheduler
      PREPARE(N+1) -> VERIFY(N) -> COMMIT(N-1)
    PREPARE cannot mutate target KV.
    VERIFY is sole tentative-KV writer.
    COMMIT publishes only target-verified tokens.

85  Authority v12
    - all previous correctness/performance requirements retained
    - reports compute + transfer queue families
    - dedicated transfer queue, when exposed, must actually be used
    - transfer-ring activity remains required
    - prepare/verify/commit pipeline stages all must execute
    - all three steady runs must remain >=85 verified TPS

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch13.zip" `
  "F:\~dev\qwen32_85tps_batch13" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch13\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Rebuild / build
---------------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run
---
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_ASYNC_SPLIT_CONTROL="1"
$env:DEEP2_Q4K_AUTOTUNE="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

New evidence
------------
GPU0_COMPUTE_QUEUE_FAMILY=...
GPU1_COMPUTE_QUEUE_FAMILY=...
GPU0_TRANSFER_QUEUE_FAMILY=...
GPU1_TRANSFER_QUEUE_FAMILY=...
GPU0_DEDICATED_TRANSFER_QUEUE=0/1
GPU1_DEDICATED_TRANSFER_QUEUE=0/1
GPU0_TRANSFER_QUEUE_SUBMITS_DELTA=...
GPU1_TRANSFER_QUEUE_SUBMITS_DELTA=...

PIPELINE_PREPARE_WINDOWS>0
PIPELINE_VERIFY_WINDOWS>0
PIPELINE_COMMIT_WINDOWS>0
TRANSFER_QUEUE_USED=PASS
THREE_STAGE_SPEC_PIPELINE=PASS

All prior fail-closed requirements remain, including:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  HOST_TRAFFIC_BOUNDED=PASS
  Q4K_AUTOTUNE=PASS
  ASYNC_DUAL_GPU_PATH=PASS

  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This is a cumulative no-new-dependency source drop. It has not been compiled
on the user's local checkout, and it is not an 85-TPS receipt until the
measured authority executable passes.
