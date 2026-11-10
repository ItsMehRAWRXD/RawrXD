# GPU quant-dot closure — existing assets and the actual remaining gap (2026-10-12)

Written after the coordinator's GPU-quant-dot directive. **The P1 GPU path is not
greenfield — it exists in-tree.** The missing piece is the call site, not the kernel.

## What already exists (verified in this worktree)

| Asset | Location | Status |
|---|---|---|
| Vulkan quant-dot shader (Q4_K x Q8_K, Q6_K x Q8_K, Q5_0, Q8_0, Q4_0) | `tools/shaders/quant_dot.comp` | present, layouts documented in-file (Q4_K: 144 B = d/dmin/scales[12]/qs[128]; Q6_K: 210 B = ql[128]/qh[64]/scales[16]/d) |
| Dispatch + batch API (`QuantDot::` namespace: `BeginQuantDotBatch`, `QueueQuantDot`, `EndQuantDotBatch`, `ExecuteQuantDot`, per-kind packed row strides) | `src/deep2/quant_dot_dispatch.cpp` / `.hpp` | present; header records RAWRXD_DEEP2_GPU_QUANT_DOT_001, "4/4 shapes on two discrete AMD GPUs" |
| Vulkan compute backend incl. `QuantDot` path (`VulkanCompute::ExecuteQuantDot` / `BeginQuantDotBatch` / `EndQuantDotBatch`) | `include/vulkan_compute.h`, `src/vulkan_compute.cpp` | present |
| r9700-stack reference kernels (MXFP4xFP8 fused MoE GEMM, Gated DeltaNet) | `3rdparty/r9700-stack/` (Apache-2.0) | vendored; HIP/ROCm — not directly usable on Windows Vulkan; use as reference only, per the coordinator's caution |

## The actual gap

The one-forward sweeps print `k-quant dot: force_cpu`, `legacy quant dot:
force_cpu`, `legacy quant type dequantised on CPU, no GPU kernel`. Those strings
are NOT in this worktree's sources (verified by search) — they come from the
forward-probe harness driving the GGUF matvec path, which currently bypasses
`QuantDot` and runs dequant-to-float + CPU matvec. So the remaining work:

1. **Wire the call site**: in the GGUF tensor/matvec path, dispatch by GGUF type
   (Q4_K/Q6_K primarily; Q5_0/Q8_0/Q4_0 follow) into `QuantDot::Run` / `ExecuteQuantDot`
   using the packed strides already computed in `quant_dot_dispatch.cpp`, instead of
   the CPU dequant matvec.
2. **No silent fallback** (coordinator requirement): when a layout/type is not
   supported by the GPU path, fail loudly with the exact tensor name and op —
   do not print `force_cpu` and continue.
3. **Parity gate**: for every wired type, compare GPU vs an independent CPU
   dequant+matvec reference on real GGUF bytes; record max-abs and RMS error,
   first-divergence index, GPU/CPU call counts, bytes transferred, kernel latency.
4. **Certification run**: full model forward on a Q4_K/Q6_K model family (V2-Lite
   Q4_K is the best-sized target) — finite logits, full-vocab argmax agreement,
   zero CPU fallbacks — then sustained decode TPS.

## Priority order preserved

1. P0 — `bigdaddyg-productivity-local` argmax=0 / max_logit=0.0 (full-logit
   distribution + all-80-blocks-executed check).
2. P0 — attention parity (first divergent tensor; RMS 0.676284 still open).
3. P1 — quant-dot call-site wiring + parity (this document).
4. P1 — Nemotron `ssm_in` GPU kernel (legacy quant dot force_cpu row).
5. P1 — real (non-proxy) attention/FFN profiler.
6. P2 — progressive 4K -> 1M context certification on nemotron-3.5-lightning:30b
   (forward prerequisite: argmax=50988 established).
7. P2 — 16/32-bit reversal benchmark (never measured this session; protocol from
   the coordinator's note).
