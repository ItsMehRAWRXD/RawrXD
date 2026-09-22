Deep2 Qwen2.5-Coder-32B — 40 TPS campaign, Batch 4 (items 16–20)
==========================================================================

Apply after Batches 1, 2, and 3.

16. RunWeightHostRoundTrip:
    one command buffer + one submit for:
      host input -> device activation -> resident GEMV -> host result.
    Also adds exact per-device queue submit counters.

17. Bind ordinary dual-row GEMV to RunWeightHostRoundTrip.
    Removes the old upload-submit + compute-submit + download-submit chain.

18. Grouped one-submit QKV / Gate+Up:
    one activation copy and one queue submit per GPU for each matrix group.

19. Row-plan cache + reusable result workspace:
    no repeated split calculation and no repeated hot-path vector allocation.

20. Adaptive row split + submit authority:
    EWMA learns relative rows/sec of the R9700 and RX7800XT and adjusts the
    simultaneous row ratio. Gate prints exact queue-submit deltas.

No new runtime dependencies. Existing Vulkan SDK is used only to rebuild the
project's own GLSL shader.

Rebuild shader (if Batch 3 shader not already rebuilt):
  powershell -ExecutionPolicy Bypass -File F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1

Build:
  cmake --build F:\~dev\build_p2 --config Release --target qwen32_40tps_gate

Run:
  $env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
  $env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
  $env:DEEP2_ROW_SPLIT_AUTO="1"
  Remove-Item Env:DEEP2_DENSE_EXEC -ErrorAction SilentlyContinue

  F:\~dev\build_p2\Release\qwen32_40tps_gate.exe `
    F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf 64

Authority remains fail-closed:
  REAL_GPU_FORWARD=1
  REAL_DUAL_ROW_GPU=1 (or FULL_RESIDENT_GPU=1)
  UNPLANNED_FALLBACKS=0
  STRICT_VIOLATION=0
  RESIDENT_REUSE=1
  BOUNDED_UPLOADS=1
  DECODE_TPS_REAL>=40.0
  DEEP2_QWEN25_32B_REAL_40TPS_001=PASS

Queue-submit deltas are telemetry in this batch, not a replacement for measured
TPS. If throughput stays below 40, retain HOLD and use the counters to choose
Batch 5.
