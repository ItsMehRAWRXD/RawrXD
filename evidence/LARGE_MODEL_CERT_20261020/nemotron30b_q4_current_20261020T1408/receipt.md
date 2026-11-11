# Nemotron 30B native GPU certification probe

**Date:** 2026-10-20 (America/New_York)
**Checkout:** `F:\rawrxd`, branch `local-30b-backend`
**Source HEAD:** `5cc3040b67ea25e0244b13e3363b0553c9a5a848`
**Executable:** `.build_nemotron_current_20261020\deep2_bench_tps.exe`
**Executable SHA-256:** `951421087FADACCCC43C1DDDEC7B503F8EF52C092EFC9D79F7BA1BAFC1BDAF88`

## Inputs

- Model: `F:\rawrxd\models\nemotron-3.5-lightning-30b-Q4_K_M.gguf`
- Model size: `25,430,738,944` bytes
- Model SHA-256: `5C19F6282F4FC51CB114CB6C876D70CA2FC3B9CF0FBD0A018D9908F4FE1F63B3`
- GGUF architecture: `nemotron_h_moe`
- Geometry: 53 blocks, embedding 2688, 32 attention heads, 32 KV heads, RoPE dimension 84
- MoE: 128 experts, 6 selected
- Prompt token IDs: `1 4019 1058 1032`
- Generation: greedy native decode, 128 output positions (`--decode 128`), Vulkan device index 0 (`AMD Radeon AI PRO R9700`)

## Environment isolation

The preflight inventory contained no `deep2_bench_tps.exe`, `deep2_agentic_loop.exe`, `rawr.exe`, or `llama-cli.exe` processes. The postflight inventory was also empty. The Ollama service was not treated as a competing loaded model workload.

## Measurements

| Metric | Result |
| --- | ---: |
| Exit code | 0 |
| Logits finite | yes |
| GPU complete | yes |
| CPU calls | 0 |
| GPU calls | 9,825 |
| Fallback | `<none>` |
| Input tokens | 4 |
| Output tokens | 128 |
| Prefill wall | 2,368.8 ms |
| Decode wall | 35,699.5 ms |
| Decode TPS | 3.557 |
| Steady decode TPS | 3.557 |
| End-to-end TPS (prefill + decode) | 0.105 |
| GPU device time | 32,466.6 ms |
| GPU time share | 85.3% |
| GPU submissions / waits | 8,066 / 8,066 |
| Device bytes peak/live | 1,010.0 / 1,010.0 MB |
| Host RAM peak/current | 24,267.1 / 1,366.2 MB |
| Weight cache hits/misses | 9,750 / 75 |
| Weight upload | 1,142.5 MB |

The generated stream is retained in `run.log` (`RUN1 GENSTREAM`). It begins `74792 99703 62555 18619 ...` and contains 128 IDs.

## Certification disposition

**PASS for this scoped native GPU execution probe:** full 128-token decode completed with finite logits, zero CPU calls, no fallback, GPU completion, and stable memory accounting on the R9700.

This receipt does **not** claim independent llama.cpp logit parity, model-quality correctness, sustained 150 TPS, or multi-GPU execution. Those remain separate gates. The earlier NVFP4 `nemotron-bolt.gguf` probe remains a real blocker because the active top-level QuantDot wrapper lacks an integrated NVFP4 dispatch path; it is recorded separately under `LARGE_MODEL_SMOKE_20261020`.

Evidence files: `run.log`, `preflight.json`, `postflight.json`, and `exit.txt`.
