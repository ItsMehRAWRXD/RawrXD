Deep2 Qwen2.5-Coder-32B — 40 TPS campaign, Batch 2 (items 6–10)
==========================================================================

This batch does NOT claim 40 TPS. It removes the next five measured/code-visible
limits and leaves DEEP2_QWEN25_32B_REAL_40TPS_001 fail-closed.

Apply after Batch 1, in numeric order.

1) 0006 — 256-lane cooperative packed GEMV. One workgroup per output row.
2) 0007 — Q4_K dot4 specialization: one uint fetch supplies four packed nibbles.
3) 0008 — persistently mapped upload/download staging buffers.
4) 0009 — two persistent dual-row worker threads; no std::async creation/GEMV.
5) 0010 — group Q/K/V and gate/up row-split calls to amortize input upload,
           worker wakeup, and host orchestration.

Build:
  powershell -ExecutionPolicy Bypass -File F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1
  cmake --build F:\~dev\build_p2 --config Release --target qwen32_40tps_gate

Authority:
  F:\~dev\build_p2\Release\qwen32_40tps_gate.exe ^
    F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf 64

Required PASS remains:
  REAL_GPU_FORWARD=1
  UNPLANNED_FALLBACKS=0
  STRICT_VIOLATION=0
  RESIDENT_REUSE=1
  BOUNDED_UPLOADS=1
  DECODE_TPS_REAL>=40
  DEEP2_QWEN25_32B_REAL_40TPS_001=PASS

If the gate remains HOLD, retain the measured receipt. Do not convert a
projection into a PASS.
