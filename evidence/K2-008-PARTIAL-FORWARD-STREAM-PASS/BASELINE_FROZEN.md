# K2-008 Partial-Forward Streaming — Frozen Baseline

**Status:** CERTIFIED PASS (unchanged baseline)  
**Frozen:** 2026-08-31  
**Harness:** `tests/k2_008_end_to_end_semantic_generation.cpp` (do not modify for Gate 10)

## Certified Run Summary

| Field | Value |
|-------|-------|
| Prompt | `hello` → token 22931 |
| Streamed | token 13889 → `"reek"` |
| Peak residency | 60.9 MiB |
| ENGINE_PATH | K2NativeStream |
| GENERATION | REAL |
| STREAMING | YES |
| FALLBACK | NONE |
| Shards | 13 |
| LAYER_DEPTH | 4 (`RAWRXD_K2_LAYERS` default) |
| Exit code | 0 |
| Duration | ~54 s |

## Evidence Log

Primary log: `F:\~dev\k2_stream_hello_20260831.log` (if present on host)

## Gate 10 Integration Note

Gate 10 in `k2_runtime_validation` invokes the **same** K2NativeStream partial-forward
path via `tests/k2_native_stream_gate.{hpp,cpp}` without altering this K2-008 source.
Claim remains bounded: real-weight, bounded-residency partial forward — not full Kimi K2
inference or semantic coherence.

## Next Milestone (post Gate 10 ×2)

Bridge MLAForward + residency into Deep2Engine/Deep2Bridge. Coherence milestone remains
61 layers + MoE + full MLA/RoPE/softmax/KV.
