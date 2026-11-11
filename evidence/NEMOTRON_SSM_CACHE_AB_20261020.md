# Nemotron SSM weight-cache A/B — 2026-10-20

This is an experimental performance receipt for the SSM parameter cache in
`RuntimeGraph::Executor::OpSsmScan`. The cache is **opt-in** with
`DEEP2_SSM_WEIGHT_CACHE=1`; the established route remains the default.

## Common controls

- Executable: `build/bin/Release/deep2_spec_bench.exe`
- Model: `models/nemotron-3.5-lightning-30b-Q4_K_M.gguf`
- Workload: code, 64-token prompt, greedy serial arm
- Generated tokens: 8 and 128
- GPU controls: `DEEP2_QUANT_ROW_TILE=8`, `DEEP2_QUANT_Q6_SHARED_TILE=1`,
  `DEEP2_QUANT_REUSE_COMMANDS=1`
- GPU: AMD Radeon AI PRO R9700
- GPU fallback: 0 in every run
- Verdict: PASS (finite serial logits) in every run

## 30B measurements

| Mode | Tokens | Prefill (ms) | Decode (ms) | Decode TPS | GPU calls |
|---|---:|---:|---:|---:|---:|
| Cache off | 8 | 3955.1 | 271.4 | 29.48 | 5364 |
| Cache on | 8 | 3824.3 | 269.8 | 29.65 | 5364 |
| Cache off | 128 | 5010.8 | 5302.5 | 24.14 | 14364 |
| Cache on | 128 | 3992.7 | 5910.6 | 21.66 | 14364 |

The 8-token result is effectively within run-to-run noise. The 128-token
result regressed, so this candidate is **not promoted** and remains opt-in.

Receipts:

- `NEMOTRON30B_SSM_AB_UNCACHED_8TOK_20261020/SPEC_BENCH_RECEIPT.txt`
- `NEMOTRON30B_SSM_AB_CACHED_8TOK_20261020/SPEC_BENCH_RECEIPT.txt`
- `NEMOTRON30B_SSM_AB_UNCACHED_128TOK_20261020/SPEC_BENCH_RECEIPT.txt`
- `NEMOTRON30B_SSM_AB_CACHED_128TOK_20261020/SPEC_BENCH_RECEIPT.txt`

## Smaller SSM isolation run

The same route on `nemotron-3-nano_4b.gguf` for 32 generated tokens measured
2554.4 ms uncached versus 2255.0 ms cached (both PASS, GPU-only). This is
useful evidence that the cache is reachable, but it does not override the
non-promotion decision for the 30B production path.

## Disposition

`DEEP2_SSM_WEIGHT_CACHE=1` is an experimental switch only. No S07/S12 gate is
closed by this receipt, and no throughput claim is made beyond the measured
runs above.
