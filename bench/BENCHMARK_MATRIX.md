# Deep2 / REAP Benchmark Matrix (2026-11-25)

Executable harness: `bench/run_matrix.ps1`. Every optimization gets an **isolated
before / after / acceptance delta** under identical conditions. No fix is accepted
without its own numbers.

## Fixed test environment (never change between before/after)
| Field | Value |
|-------|-------|
| GPU | R9700 = device 0 (`GGML_VK_VISIBLE_DEVICES=0`) |
| Model | GLM-4.7-Flash Q4_K_M |
| Context | 4096 |
| Threads | 16 |
| Repetitions | 5 |
| Temperature | 0 |
| Flash attention | on (`-fa`) |
| Offload | `-ngl 99` |
| Build | Release |
| Driver | fixed (record version) |

Record with every run: **commit, GPU, VRAM used, offloaded X/Y layers, KV cache size, n_batch, ubatch, ctx size.**

## Benchmarks
- **A — Decode TPS:** `-p 512 -n 512`; report avg / p50 / p95. Baseline 11.6–15.9. Accept ≥+10%; strong +25%; G15 target 150.
- **B — Prefill TPS:** `-p 4096 -n 0`; baseline 417 @512, 186 @4096. 1000+ major, 3000+ stretch.
- **C — GPU residency:** capture `offloaded X/Y layers`, GPU vs host memory. Metric: C−A layers.
- **D — MoE router cost:** `router_ms/token`, `expert_dispatch_ms/token`, router % of decode. (Router is currently a CPU stub at `vulkan_compute.cpp:4438-4480`; D is only meaningful after step 7.)
- **E — Quant dispatch wiring:** CPU-fallback count vs GPU-dispatch count for Q8_K/Q4_1/Q5_1/IQ4_NL. Source: `g_receipt {used_gpu, gpu_rows, cpu_rows, fallback_reason}` (`quant_dot_dispatch.cpp`, `op_linear.cpp`). Expect CPU fallback→0, GPU dispatch>0.
- **F — GPU utilization:** GPU %, VRAM %, bandwidth % (radeontop/HWiNFO). Low util ⇒ CPU/dispatch/sync bound; high ⇒ compute/bandwidth bound.
- **G — REAP vs original:** identical settings, both models; report TPS delta %, VRAM delta GB, context delta.

## Per-fix acceptance (each isolated)
| Fix | Before metric | After metric | Accept |
|-----|---------------|--------------|--------|
| Q8_K dispatch | cpu_fallback=N | cpu_fallback=0, decode Δ | +10% decode, parity PASS |
| Q4_1/Q5_1/IQ4_NL dispatch | cpu_fallback=N | 0 | parity PASS, no regression |
| Decode batching | decode TPS | decode TPS | +10% |
| GPU MoE router (step 7) | router_ms/token | router_ms/token | router <5% of decode |

## Report template
```
COMMIT: <hash>
MODEL:  GLM-4.7-Flash Q4_K_M
GPU:    R9700
RESIDENCY: <X/Y layers, VRAM>
PREFILL: Before <..> After <..> Delta <..>
DECODE:  Before <..> After <..> Delta <..>
CPU FALLBACKS: Before <..> After <..>
GPU UTIL: Before <..> After <..>
RESULT: PASS/FAIL
```

## What runs where
- A, B, C, F, G: `bench/run_matrix.ps1` (needs `llama-bench`/`llama-cli` + models — the GPU machine).
- D, E: Deep2 engine counters (`g_receipt`); D needs router timing added in step 7.
- I cannot run these here (no `.gguf`, no GPU); the harness makes your runs reproducible and comparable.