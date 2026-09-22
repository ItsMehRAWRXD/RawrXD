Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 11: items 71–75
======================================================================

No Batch-10 measured receipt accompanied this request. Batch 11 therefore
attacks RDNA kernel geometry and CPU/Vulkan launch overhead while keeping every
previous authority condition.

71  Q4_K 8-row x up-to-4-token tiled kernel
    - 256 threads / workgroup
    - eight fixed 32-thread row cohorts
    - shared 256-column activation tile
    - one tile serves eight output rows
    - explicit shared-memory reduction: no subgroup-width correctness dependency

72  Per-GPU Q4_K kernel autotuning
    - benchmark 4-row vs 8-row during warmup
    - cache winner per (rows,cols,batch) on EACH Vulkan device
    - DEEP2_Q4K_FORCE_TILE=4|8 for diagnostics
    - DEEP2_Q4K_AUTOTUNE=0 for fail-safe disable

73  Pre-recorded resident Q4_K command buffers
    - pinned weight buffer + resident input/output buffers are immutable
    - command buffer / descriptors / push constants recorded once
    - hot decode resubmits the sealed command buffer
    - cache cleared before referenced weight buffers are destroyed

74  Cost-driven speculative-window controller
    - separately measures windows 2, 3 and 4
    - chooses max observed VERIFIED TOKENS / TARGET SECOND
    - combines acceptance and actual batch-kernel efficiency automatically
    - no model-output approximation; target verification stays authoritative

75  Authority v10
    - requires autotune on both GPUs
    - requires pre-recorded Q4_K hot submissions on both GPUs
    - requires measured cost controller coverage of windows 2/3/4
    - reports 4-row vs 8-row use
    - retains three independent >=85 verified TPS runs

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch11.zip" `
  "F:\~dev\qwen32_85tps_batch11" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch11\*.patch" |
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
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"
$env:DEEP2_Q4K_AUTOTUNE="1"

Remove-Item Env:DEEP2_Q4K_FORCE_TILE -ErrorAction SilentlyContinue

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

New evidence
------------
GPU0_Q4K_AUTOTUNE_RUNS_DELTA>0
GPU1_Q4K_AUTOTUNE_RUNS_DELTA>0
GPU0_RECORDED_Q4K_SUBMITS_DELTA>0
GPU1_RECORDED_Q4K_SUBMITS_DELTA>0

WINDOW2_ATTEMPTS>0
WINDOW3_ATTEMPTS>0
WINDOW4_ATTEMPTS>0
COST_CONTROLLER_SELECTIONS>0

Q4K_AUTOTUNE=PASS
RECORDED_Q4K_HOTPATH=PASS
COST_DRIVEN_SPEC_WINDOW=PASS

All prior fail-closed requirements still apply:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  HOST_TRAFFIC_BOUNDED=PASS
  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85
  DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This ZIP is source, not measured performance evidence. Apply/build/run before
minting any 85-TPS claim.
