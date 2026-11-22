# Deep2 GPU Failure Diagnosis — 2026-11-22

## Test: deep2_multitoken_decode_parity (commit 8ac2bfcb0d)

### Behavior
- **Without tracing**: hangs indefinitely (ctest timeout) — a timing-dependent race.
- **With DEEP2_SUBMIT_TRACE=1**: completes cleanly (exit 1), no hang. Tracing's I/O delays mask the race.
- **Numerical result**: `S03_PREFILL_PARITY maxAbs=0.495`, `S03_HIDDEN_PARITY first_divergent_pos=0 maxAbs=2.13`, `S03_ABORT stage=prefill_parity failures=2 decode=NOT_RUN`.

### Vulkan submission trace (stderr, DEEP2_SUBMIT_TRACE=1)
- All `endSubmitWait` fence waits complete — **no VK_TIMEOUT, no device-lost** logged.
- Submissions: work_kind=1 (6.5 MB, 53 MB), work_kind=2 (8 KB, 22 KB, 128 KB), all `fused=0` (unfused path).
- Engine shutdown sequence completes normally (`~Deep2Engine END`, `[StreamEngine] Shutdown`).

### Diagnosis
1. **The hang is NOT a fence timeout** — all fence waits complete in the traced run. It is a **timing-dependent race** in the unfused path (likely a synchronization/ordering issue that tracing's I/O delays mask).
2. **The numerical divergence is the real defect** — serial vs batched prefill produce different hidden states at **position 0** (maxAbs 2.13), before any cross-position accumulation. This rules out KV-cache/position-indexing as the primary cause.
3. The position-0 causal invariant `A0=V0` is the isolation tool: at position 0, attention has one visible token, so the attention output must equal V0. The first divergent boundary (Q/K/V → RoPE → causal mask → AV → output → residual → FFN) determines the fix.

### Next step
Capture per-op hidden states at position 0 for serial vs batched prefill (using the runtime_graph_executor OpTraces) to identify the first divergent operation. The concurrent worker's recent fixes (attn_kv_a_mqa transpose `9d0ec3414b`, MLA K/V stride `53edf653c6`) target the MLA path; the TinyLlama non-MLA batched-prefill path needs the same op-level isolation.

### Disposition
```
GPU_HANG=RACE (not fence timeout; tracing avoids it)
GPU_NUMERICAL_PARITY=FAIL (serial vs batched prefill, pos 0, maxAbs 0.495)
FENCE_WAITS=ALL COMPLETE (no timeout/device-lost in trace)
DEFECT_LOCUS=BATCHED PREFILL (causal mask / GEMM accumulation / dispatch geometry)
PROMOTE=0 CERTIFIED=0 RELEASE=HELD
```