# S07 speculative decoding measurement receipt — 2026-10-20

Status: **OPEN**. The native speculative path completed both controlled workloads with exact greedy stream agreement and finite logits, but it did not produce an end-to-end speedup or a target-forward reduction.

## Reproducibility

- Repository: `F:\rawrxd`
- Branch: `local-30b-backend`
- Build target: `deep2_spec_bench` (Release), exit code `0`
- Executable SHA-256: `96906CA228A21947B844F41978E7A8386955952CB1000946161E6B714881ACD8`
- Command:
  `build/bin/Release/deep2_spec_bench.exe --model F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --workload both --tokens 128 --gamma 4 --ngram 3 --draft repeat --evidence evidence/S07_SPEC_RUN_20261020`
- Model SHA-256: `9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0`
- Device: AMD Radeon AI PRO R9700 through Vulkan; `cpu_calls=0` on both arms
- Runtime verdict: `VERDICT=PASS` for the benchmark's correctness checks; this does not close S07.

## Controlled results

| Workload | Emitted | Proposed | Accepted | Acceptance | Serial decode | Spec decode | Decode delta | Spec/serial TPS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Code | 128 | 164 | 15 | 9.1% | 28,105.5 ms | 55,418.4 ms | +27,312.9 ms | 0.51x (4.55 → 2.31) |
| Prose | 128 | 32 | 0 | 0.0% | 28,938.8 ms | 34,434.6 ms | +5,495.8 ms | 0.84x (4.42 → 3.72) |
| **Combined** | **256** | **196** | **15** | **7.7% of proposals** | — | — | — | **no speedup** |

Total wall time including prefill was 47,075.3 ms serial versus 72,687.0 ms speculative for code (+25,611.7 ms), and 58,049.6 ms serial versus 63,579.6 ms speculative for prose (+5,530.0 ms).

The code arm reported 36,098 serial GPU calls versus 62,801 speculative GPU calls; prose reported 47,208 versus 52,872. The receipt therefore demonstrates no target-forward/submission reduction on this implementation. The reported `serial_steps` counters (72 and 120) are accounting fields, not proof of reduced target forwards.

Both workloads produced `128/128` greedy stream agreement. Both arms reported no nonfinite logits. The code arm had 41 verification rounds, 15 accepted tokens, 41 replacements, and 32 zero-accept rounds. The prose arm had 8 rounds, 0 accepted tokens, 8 replacements, and 8 zero-accept rounds.

## Validation and alignment observations

No Vulkan validation-layer, alignment, or runtime error/warning messages were present in the captured benchmark log. Device selection, Vulkan initialization, descriptor/pipeline setup, and cleanup completed normally. The build log contains only existing compiler warnings from third-party ggml sources.

## Certification decision

S07 remains **OPEN**. Correctness is demonstrated for this 128-token pair, but acceptance is low and speculative execution is slower than serial in both workloads. Close requires an implementation that accepts drafts and measurably reduces target work and total wall time, followed by repeated controlled runs.

Raw artifacts:

- `evidence/S07_SPEC_RUN_20261020/run.log`
- `evidence/S07_SPEC_RUN_20261020/SPEC_BENCH_RECEIPT.txt`
- `evidence/S07_SPEC_RUN_20261020/spec_bench.json`
