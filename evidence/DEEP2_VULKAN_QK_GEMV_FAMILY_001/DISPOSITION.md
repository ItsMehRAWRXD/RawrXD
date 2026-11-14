# DEEP2_VULKAN_QK_GEMV_FAMILY_001 — Disposition

`WS3_DEEP2_VULKAN_QK_GEMV=RELATED` — family validation expanded and sealed; **not** CERTIFIED.

## What closed
- Exact-SHA verify of REPORTED Q6K FORCE_SPV: commit `37d8dc32cb` + sealed EXE `CEBA0DE4` artifacts (HOST_GEMV=0, coherent stdout, packed Q4/Q6 ops).
- Q8 shape matrix PASS across four supported shapes; Q5/Q3/Q2 baseline PASS.
- Q4_K product-shape numeric within cert thresholds on measured cert EXE; FALLBACK=0.
- Q6_K attn_v host↔SPV PARITY_OK on probe EXE (RELATED).

## What did not close
- Q4_K overall `STREAMER_GPU_Q4K_GEMV_001=FAIL` (tps 0.256 < 0.4) — numeric ≠ gate PASS.
- Packed GEMM multi-batch matrix OPEN.
- Live tip FORCE_SPV remasure incomplete / tip churn — **no CROSS_SHA** from CEBA0DE4.
- Hidden host fallback never credited as Vulkan PASS.

## Law
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `GATE_STOP=1` · `CROSS_SHA_CREDIT=0`
