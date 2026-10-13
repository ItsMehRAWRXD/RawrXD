# Certification Re-Verification at HEAD `1b43b36a54`

Date: 2026-10-13. Per the integration requirement, prior PASS results are NOT
promoted: Gates 4 and 6 were re-executed against binaries rebuilt from the
sources committed at `1b43b36a54` (build: `tools\build_deep2_parity_trace.bat`,
exit 0), on llama3.2:3b (Q4_K), seed tokens [1, 185].

## Re-verified at this revision

| Gate | Config | Result | Command |
|------|--------|--------|---------|
| 4 | CPU-native | **PASS** — 196 dots, all `cpu forced=1`, 0 unauthorized fallbacks, finite outputs, 395 ops bound | `deep2_parity_trace --model M --tokens "1" --gate4 cpu` |
| 4 | GPU-native | **PASS** — 196 dots, all `vulkan`, `gpu_calls=197 cpu_calls=0 fallback=none` | `deep2_parity_trace --model M --tokens "1" --gate4 gpu --gpu` |
| 6 | Multi-token KV | **PASS** — GENSTREAM `26957 320 32482 34190 101453 74541 8 104380`, identical to every prior CPU and llama.cpp run | `deep2_parity_trace --model M --tokens "1 185" --generate 8` |

Gates 1 and 3 were certified at `a551012de`; they are NOT re-asserted here.
Re-running them at this HEAD requires the full CMake configure/build and the
GGUF geometry auditor, and remains a recorded TODO rather than a promoted
claim. No gate result above is inherited: each line was produced by a fresh
execution of a binary built from this revision's sources.

## Still open

- Gate 2: primitive capability manifest emitted from the authoritative
  registry (`quant_parity_cert` -> `rawr capabilities` with stale/contradiction
  rejection).
- Gate 5: full-logit parity across multiple prompts/positions/layers, with the
  drift-vs-boundary-flip decomposition applied per divergence.
- Gate 7: production-loop benchmark (no diagnostic tracing), wall-clock TPS
  with the same no-fallback dispatch counters; the 685 ms/token position-1
  figure remains a harness-path lower bound, and the 150 TPS target is open.
