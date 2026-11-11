# S07 adaptive verifier and draft-policy receipt — 2026-10-20

Status: **OPEN**. This change adds explicit verifier accounting and lowers the default adaptive-disable threshold from 8 to 2 consecutive zero-accept rounds. It preserves greedy output and avoids continuing known-unproductive batches, but does not yet deliver repeatable code-workload speedup.

## Source and build

- Branch: local-30b-backend
- Base measurement commit: 8ce32ea5cc
- Build target: deep2_spec_bench Release, exit 0
- Executable SHA-256: 2CDFAA6C4ADA3285CE190086B244ED71E1AB31864EDEF5C70E56433412A9814F
- Model SHA-256: 9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0
- Device: AMD Radeon AI PRO R9700, Vulkan
- All runs: 128 generated tokens, gamma 4, zero CPU calls, exact 128/128 stream agreement, zero nonfinite logits.

## Adaptive repeat drafter

With --draft repeat and max_consecutive_zero=2:

| Workload | Proposed / accepted | Verify batches / positions | Repairs | Serial fallback tokens | Decode speed |
| --- | ---: | ---: | ---: | ---: | ---: |
| Code | 12 / 3 (25.0%) | 3 / 15 | 3 | 118 | 4.30 vs 4.51 TPS (0.95x) |
| Prose | 8 / 0 (0.0%) | 2 / 10 | 2 | 123 | 4.23 vs 4.08 TPS (1.04x) |

The earlier threshold-8 run measured 15/164 accepted code proposals at 0.51x and 0/32 prose proposals at 0.84x. Early disable materially reduced wasted verifier work, but the code workload still did not accelerate and the prose gain is a single controlled run.

## Prompt-lookup drafter

With --draft prompt and max_consecutive_zero=2:

| Workload | Proposed / accepted | Verify batches / positions | Repairs | Serial fallback tokens | Decode speed |
| --- | ---: | ---: | ---: | ---: | ---: |
| Code | 92 / 42 (45.7%) | 23 / 115 | 18 | 44 | 3.54 vs 4.52 TPS (0.78x) |
| Prose | 50 / 35 (70.0%) | 13 / 63 | 5 | 74 | 4.23 vs 4.50 TPS (0.94x) |

These runs show that the remaining bottleneck is verifier cost: the target executes a full sequence-level graph pass plus serial KV repair, and the current attention/norm/KV stages remain token-minor. Prompt acceptance is not enough to amortize those costs.

## Certification

S07 remains **OPEN**. The new counters distinguish verify_batches, verify_positions, repair_steps, and serial_fallbacks from aggregate GPU calls. Closing requires repeated end-to-end speedup with fewer target positions/forward work, while retaining exact streams and finite logits.

Raw artifacts:

- evidence/S07_VERIFY_COUNTER_RUN_20261020/
- evidence/S07_ADAPTIVE_RUN_20261020/
- evidence/S07_ADAPTIVE_128_RUN_20261020/
- evidence/S07_PROMPT_DRAFT_RUN_20261020/
