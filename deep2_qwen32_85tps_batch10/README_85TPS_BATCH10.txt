Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 10: items 66–70
======================================================================

No Batch-9 measured receipt accompanied this request. Batch 10 attacks kernel
efficiency and launch/preparation overhead directly.

66  Q4_K 4-row x up-to-4-token tiled kernel
    - one 256-thread workgroup computes 4 output rows
    - four fixed 64-thread row cohorts
    - shared 256-column activation tile
    - activation tile reused across 4 output rows
    - no subgroup-size dependency

67  Runtime selector + Q4_K byte/time counters
    - matrices with rows>=4 select tiled kernel automatically
    - small tails retain previous kernel
    - exact bytes and GPU timestamp nanoseconds accumulated

68  Ping-pong speculative arenas
    - two resident 1..4-token activation arenas
    - immutable next-window preparation can target inactive arena
    - target KV writes remain serialized and authoritative

69  Kernel bandwidth authority plumbing
    - per-card Q4_K batched bytes
    - per-card GPU nanoseconds
    - 4-row kernel invocation count
    - speculative arena flip count

70  Authority v9
    - ALL prior requirements remain
    - new tiled Q4_K kernel must run on BOTH GPUs
    - ping-pong arena path must run
    - reports measured effective Q4_K GB/s/card
    - still requires all three steady runs >=85 verified output TPS

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch10.zip" `
  "F:\~dev\qwen32_85tps_batch10" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch10\*.patch" |
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

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

New evidence
------------
GPU0_Q4K_EFFECTIVE_GBPS=...
GPU1_Q4K_EFFECTIVE_GBPS=...
GPU0_Q4K_4ROW_OPS_DELTA>0
GPU1_Q4K_4ROW_OPS_DELTA>0
SPEC_ARENA_FLIPS_DELTA>0
TILED_Q4K_KERNEL=PASS
SPEC_PINGPONG=PASS

Final fail-closed law remains:
  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS
  HOST_TRAFFIC_BOUNDED=PASS
  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85
  DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

Do not infer 85 TPS from the kernel GB/s counters. The verified end-to-end
three-run gate remains the performance authority.
