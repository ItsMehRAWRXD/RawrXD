# MODEL_GENIE_NATIVE_FORWARD_001 — Gate 7: performance certification (first run)

Date: 2026-10-13. Config: llama3.2:3b (Q4_K), seed [1,185], 8 greedy tokens,
Radeon AI PRO R9700, native Vulkan forward (no CPU pin), Windows x64,
harness `deep2_parity_trace --gpu --generate 8`.

## Numerical result on the GPU path (not just dispatch)

GENSTREAM: 26957 320 32482 34190 101453 74541 8 104380
gpu_calls=8865  cpu_calls=0  fallback=<none>

The generated token IDs are IDENTICAL to the CPU-native run and to llama.cpp
(8/8), and the per-step logits match the CPU path within the decomposed
drift (~0.2-3%). GPU/CPU numerical equivalence is therefore certified on the
generation stream, not only on dispatch counters.

## Measured timing (this harness path)

- first forward (pos 0, includes Vulkan pipeline warm-up):  2674.6 ms
- second position (pos 1):                                685.2 ms  (~1.46 tok/s)
- generated positions: per-position ms are not emitted on the generation
  path (only seed positions print timings) — see Scope.

## Scope and what is NOT certified here

- This harness executes the graph op-by-op and syncs per op (diagnostic path
  with value capture available); it is NOT a production decode loop. The
  measured tok/s is a lower bound for the native forward, not a product TPS.
- The 150 TPS acceptance target (audit item 50) remains OPEN and must be
  measured on the production decode loop (deep2_decode_probe or the engine
  decode entry) with prefill/decode separated, GPU utilization, VRAM
  accounting and a reproducible benchmark config. That is the remaining Gate 7
  work; the numbers above are the first native-GPU measurement, recorded
  honestly as a harness-path bound.
