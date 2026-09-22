Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 15: items 91–95
======================================================================

No Batch-14 measured receipt accompanied this request. Batch 15 attacks
whole-layer command construction and speculative-window boundary overhead.

91  Pre-recorded QKV / Gate-Up group commands
    - immutable resident input, pinned weights, resident group outputs
    - one sealed command stream per group geometry
    - no descriptor/push/command rebuild in hot decode

92  GPU speculative accept-prefix reducer
    - target top-1 IDs compared with proposal IDs on GPU
    - returns only:
        accepted prefix length
        replacement target token
        all-accepted bonus predictor
    - exact greedy semantics unchanged

93  Resident verified-hidden handoff
    - last accepted proposal hidden stays on GPU0
    - next speculative window can begin from resident hidden
    - host hidden remains available for debug/parity only

94  Timeline layer-group chaining
    - QKV -> attention/O -> GateUp -> Down/residual
    - dependencies expressed with timeline values when supported
    - does not reorder transformer dependencies

95  Authority v14
    New required live paths:
      RECORDED_GROUP_HOTPATH=PASS
      GPU_ACCEPT_PREFIX=PASS
      RESIDENT_HIDDEN_HANDOFF=PASS
      LAYER_TIMELINE_CHAIN=PASS (when timeline enabled)

    Every older exactness/residency/dual-GPU requirement stays in force.
    All three measured steady runs must still independently reach >=85 TPS.

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch15.zip" `
  "F:\~dev\qwen32_85tps_batch15" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch15\*.patch" |
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
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_ASYNC_SPLIT_CONTROL="1"
$env:DEEP2_Q4K_AUTOTUNE="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

New evidence
------------
GPU0_RECORDED_GROUP_SUBMITS_DELTA>0
GPU1_RECORDED_GROUP_SUBMITS_DELTA>0
GPU_SPEC_ACCEPT_OPS_DELTA>0
VERIFIED_HIDDEN_HANDOFFS_DELTA>0

RECORDED_GROUP_HOTPATH=PASS
GPU_ACCEPT_PREFIX=PASS
RESIDENT_HIDDEN_HANDOFF=PASS
LAYER_TIMELINE_CHAIN=PASS

All previous fail-closed requirements remain, including:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  HOST_TRAFFIC_BOUNDED=PASS
  Q4K_AUTOTUNE=PASS
  ASYNC_DUAL_GPU_PATH=PASS
  THREE_STAGE_SPEC_PIPELINE=PASS
  TIMELINE_CHAIN_USED=PASS when timeline is supported

  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This archive is cumulative source only. It has not been compiled on the user's
local checkout and is not measured performance evidence.
