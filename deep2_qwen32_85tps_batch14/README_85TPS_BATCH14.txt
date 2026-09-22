Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 14: items 86–90
======================================================================

No Batch-13 measured receipt accompanied this request. Batch 14 attacks host
synchronization around compute->transfer dependencies.

86  Timeline semaphore runtime
    - Vulkan 1.2 timeline semaphore capability
    - enabled only when physical device exposes it
    - fence path remains fallback
    - timeline signal/wait counters

87  GPU-side compute -> transfer chain
    - Q4_K compute signals timeline value N
    - transfer queue waits on N entirely on GPU
    - transfer signals N+1
    - host waits only for final data dependency
    - no host compute-completion wait merely to submit transfer

88  Persistent async command-buffer ring
    - four preallocated compute command buffers + fences
    - Batch-12 Q4_K async tickets reuse them
    - no per-submit command allocation/free in steady state

89  Overlap-efficiency controller
    overlap_eff =
      (gpu0_ns + gpu1_ns - wall_ns) / min(gpu0_ns,gpu1_ns)
    - EWMA measured concurrency
    - poor overlap increases existing faster-lane bias
    - strong overlap retains stable split
    - bounded 20/80 minimum/maximum row ownership

90  Authority v13
    - every previous predicate retained
    - timeline capability is reported per GPU
    - if timeline is enabled on a card, timeline chains must execute
    - async command ring must execute on BOTH GPUs
    - timeline unsupported is a supported fallback, not fake failure
    - final real authority still requires three >=85 verified TPS runs

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch14.zip" `
  "F:\~dev\qwen32_85tps_batch14" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch14\*.patch" |
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
GPU0_TIMELINE_ENABLED=0/1
GPU1_TIMELINE_ENABLED=0/1

GPU0_TIMELINE_CHAINS_DELTA=...
GPU1_TIMELINE_CHAINS_DELTA=...

GPU0_ASYNC_CMD_RING_REUSE_DELTA>0
GPU1_ASYNC_CMD_RING_REUSE_DELTA>0

TIMELINE_CHAIN_USED=PASS
ASYNC_COMMAND_RING=PASS

All earlier fail-closed requirements remain:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  HOST_TRAFFIC_BOUNDED=PASS
  Q4K_AUTOTUNE=PASS
  ASYNC_DUAL_GPU_PATH=PASS
  THREE_STAGE_SPEC_PIPELINE=PASS

  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This is source only. It has not been compiled or benchmarked on the user's
checkout. No 85-TPS claim is valid until the measured authority gate passes.
