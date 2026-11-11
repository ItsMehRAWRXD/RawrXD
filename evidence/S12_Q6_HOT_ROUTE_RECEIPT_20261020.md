# S12 / Q6 hot-route acceleration receipt — 2026-10-20

The guarded row-4 Q6 shared-tile shader and command-buffer reuse route were exercised on the isolated AMD Radeon AI PRO R9700 with TinyLlama Q4_K_M. The route is controlled by `DEEP2_QUANT_ROW_TILE=4`, `DEEP2_QUANT_Q6_SHARED_TILE=1`, and `DEEP2_QUANT_REUSE_COMMANDS=1`; no CPU fallback occurred.

## Sustained 128-token result

| configuration | code serial TPS | code spec TPS | prose serial TPS | prose spec TPS | output / logits | CPU calls |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| row4 + Q6 shared + reuse | 31.02 | 29.64 | 29.07 | 27.63 | 128/128, finite | 0 |
| row4 + Q6 shared + reuse + spin wait | 32.32 | 29.47 | not run | not run | 128/128, finite | 0 |
| row4 + Q6 shared + direct I/O | 28.01 | 26.14 | not run | not run | 128/128, finite | 0 |
| row4 + Q6 shared + reuse + spin + wide batch | 28.37 | 27.90 | not run | not run | 128/128, finite | 0 |

The 31.02/29.07 result is sustained over 128 generated tokens and is the route authority. Spin-wait improved one code control to 32.32 TPS but is not promoted as a universal default; direct I/O and wide batching regressed. The four-token hot probe reached 44.41 TPS, but it is explicitly exploratory and not a sustained certification.

## Correctness and fail-closed controls

Every promoted-route arm produced identical greedy streams, finite logits, and zero CPU calls. The attempted subgroup-vector Q6 batch shader was rejected: differential validation reported `max_abs=20.4811039` and greedy divergence, so its artifact remains an unpromoted experiment.

S07 acceleration remains OPEN because speculative verification still increases total work (25%/0% acceptance in the 128-token code/prose runs). S12 remains FAIL against the 150 TPS requirement. This receipt certifies a measured optimization route, not a release claim.

Artifacts:

- `evidence/S07_Q6_HOT_ROUTE_128_20261020/`
- `evidence/S07_Q6_HOT_SPIN_128_20261020/`
- `evidence/S07_Q6_HOT_DIRECT_128_20261020/`
- `evidence/S07_Q6_HOT_COMBINED_128_20261020/`
- `evidence/S07_Q6_HOT_ROUTE_4_20261020/`
- `evidence/S07_Q6_WT_SHADER_VALIDATE_4_20261020/`

## Post-build artifact revalidation

After `scripts/compile_quant_row4_shaders.ps1` and a clean Release rebuild, the route selected `F:\rawrxd\tools\shaders\quant_dot_row4_q6tile.spv` and reproduced code serial 31.15 TPS / speculative 29.89 TPS over 128 tokens. Both streams were exact 128/128, finite, and CPU-call free. Receipt: `evidence/S07_Q6_HOT_ROUTE_128_R2_20261020/`.

Current artifacts: row4 source `CB8DE5EC316C580C7DE1C008441BE7E524113A517BD334716298B5CBD99CE477`, Q4 SPIR-V `98A6FBA75CCF7318F14C2ECBDC148F93CF1EB7F12BC88B83CC8A4B606B768432`, Q6 shared-tile SPIR-V `649A83E958A76B885B227DC2E61FB2F3990D1A47A5EEB5FB55FF6F9FA01AEECE`.
