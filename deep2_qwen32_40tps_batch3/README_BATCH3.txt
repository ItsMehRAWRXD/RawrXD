Deep2 Qwen2.5-Coder-32B — 40 TPS campaign, Batch 3 (items 11–15)
==========================================================================

Apply after Batch 1 and Batch 2, in numeric order.

11. Throughput-balanced dual row split.
    The old helper used VRAM capacity and gave the 32GB card ~2/3 of every
    matrix. This batch defaults to 50/50, tunable with per-GPU weights.

12. AMD subgroup/wave reduction for Q4_K GEMV.
    Replaces the full 256-lane shared-memory reduction tree.

13. Persistent descriptor cache.
    Unique resident buffer tuples allocate/update descriptors once.

14. Reusable fused submit objects.
    One persistent command buffer, fence, and timestamp query pool per GPU
    replaces per-token create/destroy/free churn.

15. Real dual-row dense product lane.
    Dense two-GPU Qwen defaults to host-orchestrated, strict dual-row weight
    GEMVs so both memory systems work on every heavy matrix. This is recorded
    honestly as REAL_DUAL_ROW_GPU, not FULL_RESIDENT_GPU.

Shader rebuild:
  powershell -ExecutionPolicy Bypass -File F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1

Build:
  cmake --build F:\~dev\build_p2 --config Release --target qwen32_40tps_gate

Run:
  $env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
  $env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
  Remove-Item Env:DEEP2_DENSE_EXEC -ErrorAction SilentlyContinue
  F:\~dev\build_p2\Release\qwen32_40tps_gate.exe `
    F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf 64

Authority:
  REAL_GPU_FORWARD=1
  REAL_DUAL_ROW_GPU=1  (or FULL_RESIDENT_GPU=1)
  UNPLANNED_FALLBACKS=0
  STRICT_VIOLATION=0
  RESIDENT_REUSE=1
  BOUNDED_UPLOADS=1
  DECODE_TPS_REAL>=40.0
  DEEP2_QWEN25_32B_REAL_40TPS_001=PASS

Do not mint PASS from projections. If <40 TPS, retain HOLD and use the
receipt to choose Batch 4.
