# Qwen4Exp full-model production gate ledger — 2026-10-20

Status: **BLOCKED — no Qwen4Exp full-model certificate**.

## Evidence/repo mismatch

The connected `ItsMehRAWRXD/RawrXD` GitHub default `main` HEAD examined is `033a8acb55d46d2fc22a84428e81f3167a0c3897`, latest visible main commit October 18, 2026. Its repository tree does not contain the `deep2_gpu_certify.cpp`, `VulkanWeightStreamer`, or `Qwen4Exp` paths described for the user's more recent local F: worktree. Examined `master`, `model-correctness`, and `agentic-ide-production` branches likewise did not expose those exact production files. Consequently this is an **architectural, provisional** gate inventory, not an audited exhaustive inventory of current local source.

Do not commit any stand-alone reference implementation over a divergent production tree. Synchronize the exact local worktree first and protect its Llama evidence/commit hash.

## Fail-closed gates to resolve and independently verify

| Gate | Required proof | Observed status in accessible source | Failure mode |
|---|---|---|---|
| 01 GGUF manifest and architecture dispatch | All metadata, layer types, positions and tensor counts; no inferred defaults | No current Qwen4Exp certifier source accessible | reject load |
| 02 Quant and tensor binding | Shapes, layout strides, sharded offsets, quant kernels verified | no direct evidence | reject GPU admission |
| 03 GR read | Group RMSNorm (delta gamma), low-rank SiLU/sigmoid stream mix | **isolated CPU arithmetic-contract tested only** | reject unsupported GPU graph |
| 04 GR write | Per-stream `2*sigmoid` injection, no reduced single residual | **isolated CPU arithmetic-contract tested only** | reject |
| 05 GDN | Q/K/V gate layouts, recurrent state, convolution update, masks, position handling | no current local evidence | reject |
| 06 QSA | Indexer Q/K, compressed-block scoring/top-K, rotary position, exact causal selection | no current local evidence | reject |
| 07 QSA KV cache | Dynamic window, incomplete block, long-context indexer and KV consistency | no current local evidence | reject |
| 08 PLE n-gram | uint64 hashing, index bounds, configured n-gram heads, real token IDs | no current local evidence | reject |
| 09 PLE convolution | Dilated depthwise conv, layer placement, decode cache and resets | no current local evidence | reject |
| 10 MoE | softmax top-K router, selected experts, shared expert, weight scaling | no current local evidence | reject |
| 11 Residency/transfer | every required tensor/expert ready before device dispatch, no stale tickets, no eviction of active dispatches | partial historical reported contract tests; not Qwen4Exp E2E | reject |
| 12 Vulkan GPU-only | Every production dispatch supported, 0 CPU fallback including PLE and host conversions | no current Qwen4Exp evidence | reject |
| 13 Output head | final GR combine-less read, vocabulary projection, final logits all finite | no current Qwen4Exp evidence | reject |
| 14 Full-model independent parity | all actual decoder layers, positions, logits with independent oracle and approved thresholds | **not passed** | no certificate |
| 15 Autoregressive decode | deterministic multi-token decode, EOS/stop reason, repeated generation, cache correctness | **not passed** | no certificate |
| 16 Regression | Llama 3.2 21/21 model receipt and 24/24 generation remain byte-identical and reproducible | user-reported evidence, protected (not accessed or modified here) | block merge if regression |
| 17 Evidence provenance | model SHA, config, build SHA, driver/device IDs, exact flags, full logs/receipts | no new certificate | no certificate |

## Immediate viable integration target

**GR read/write** using preexisting certified GEMV, RMSNorm, activation and elementwise Vulkan primitives (after checking primitive signatures in the actual local tree). Numerical reference and unit tests are provided here; GPU path is not added. The GPU certifier must not call the CPU numerical reference, and `cpu_calls` must stay zero for the whole model.

Next implement in the local production `ExecutionIR` graph with: a distinct GR read op, a GR residual-inject op, and the final combine-less output GR; preserve multi-stream state throughout GDN/QSA/MoE. Require independent per-operator parity, then full-model certification evidence. No intermediate operator PASS may set `FULL_MODEL_CERTIFIED`.

## Benchmark pause

No R9700/Vulkan benchmarks were run here. The previously requested pause remains active until a direct resume instruction. The test in this package is CPU-only and independent from the local Deep2 runtime.
