# r9700-stack integration notes (RawrXD / Deep2)

Vendored reference source: **`3rdparty/r9700-stack/`** — upstream
<https://github.com/bkvargyas/r9700-stack> @ v0.3.2 (2026-10-10), Apache-2.0
(`3rdparty/r9700-stack/LICENSE`; upstream NOTICE item 1 confirms the LRU kernels
are Apache-2.0 with their own LICENSE preserved). Its `.git` was moved to
`F:\rawrxd-quarantine-nested-gits\_3rdparty_r9700-stack.git` so the vendored
tree commits as files.

**Status: reference material, NOT drop-in replacements.** Everything upstream
targets HIP/ROCm 10 + vLLM on Linux with matched R9700s. Deep2 runs native
Windows Vulkan/HIP-compute on a heterogeneous R9700 32 GB + RX 7800 XT 16 GB
pair with 64 GB RAM. Per-component analysis below; nothing was wired into the
active build path. Integration candidates in priority order.

## Ported this session

| Component | Where in Deep2 | Validation |
|---|---|---|
| Deterministic expert-cache LRU policy (host-side port of the semantics in upstream `kernels/third_party/davetha/r4d_lru.hip`; stamp refresh on routing, victim = argmin `(stamp, slot)` over slots not routed this step, misses emitted in expert-id order, no atomics → TP-rank-identical) | `src/deep2/r9700/R9700ExpertLruPolicy.hpp` + `R9700ExpertLruPolicy_test.cpp` | Compiled with clang++ 23.1.2 (`-std=c++17`); 5 workloads, ~50k steps, capacity-pinning + eviction + determinism + map-consistency invariants PASS |

The port exists so Deep2's residency managers
(`src/deep2/ElasticResidencyManager.hpp`, `ResidencyLease.hpp`,
`ResidencyManager.hpp`, `MoEPlaceLiveCounters.hpp`, `K2TensorResidencyBridge.hpp`)
have one documented, testable eviction contract. It does not touch device
state by itself.

## P0 — MoE expert streaming cache (upstream `kernels/third_party/davetha/r4d_lru.hip`)

- **Their design.** Two capturable device kernels per MoE layer:
  `r4d_lru_manage` (one workgroup: mark routed, refresh resident stamps, pick
  victims by argmin stamp over non-routed slots, rewrite `table`/`map_cold`,
  emit the ordered miss list) and `r4d_lru_gather` (six per-expert buffers
  — `w1, w2` plus `ws_t`/`wref` scale rows — copied from UVA **pinned host**
  tensors, 16 B/lane).
- **Why it matters here.** Deep2's MoE residency
  (`K2MoEWeights.hpp`, `K2NativeMoEFfn.hpp`, `ElasticResidencyManager`,
  `MoEExpertResidencyPlace.hpp`, plus the mirror-manager pair
  `DualGpuMirrorManager`/`ExchangeMirror`) already streams experts; the LRU
  gives TP-stable victim choice and a host-memory fallback tier that matches
  the two-GPU Flash-Next headline (experts in host RAM, ~120 GB RAM host).
  Deep2 host has 64 GB RAM → only partial adoption viable for 28 GB+ models;
  per-layer subsets only.
- **Next steps.** (1) Wire `ExpertLruPolicy` as the host-side admission oracle
  in front of `ElasticResidencyManager`, feeding a future device port of
  `lru_manage`. (2) Parity gate vs. current residency policy on
  `bench_frag.gguf`/`DeepSeek-V2-Lite` with `tools/verify_e2e_cert.py`-style
  receipts. (3) Device port to Vulkan compute = translate the 256-thread
  block reductions (`blkSum`/`blkMin`/`blkExScan`) into SubgroupScope
  shared-memory invocations under `tools/shaders/quant_dot.comp` conventions.

## P0 — MXFP4 x FP8 fused MoE GEMM (upstream `kernels/r9k_moe_mxfp4a8.hip`, 118 KB)

- **Their design.** Grouped WMMA GEMM at `MOE_BLOCK=16` rows; per-token
  activation quant fused into the A-load; routing + top-k sum folded in the
  epilogue; folded-exponent unpack (`FoldTab`, `kMag`) carrying `2^(Wref-127)`
  to the epilogue instead of rescaling activations; launcher surface
  `extern "C" int r9k_moe_mxfp4a8(...)` / `r9k_moe_nvfp4a8(...)`.
  `r9k_silu_mul_quant_fp8` / `r9k_quant_rows_fp8` are companion kernels.
- **Deep2 mapping.** Replaces/weights against
  `src/deep2/K2MLA_FusedQ4KT.hpp`, `K2MLA_GpuGemv.hpp`, `FusedKQuantGEMV.hpp`,
  `HostQ8GemvSafe.hpp`, `Deep2MatrixWrapper` (the DeepSeek V2/V3.2-Exp /
  Kimi K2 Q4_K_M path is the same MXFP4-ish block layout, so the fold-table
  trick is the interesting piece: `K2MLAAttention`/`K2MlaQkvTiming` show our
  Q4_K dequant path dominates the step).
- **Constraint.** gfx1201 WMMA is not Vulkan; a Vulkan `quant_dot`-class port
  must go through `VK_KHR_shader_bfloat16` + subgroup paths. Port effort is
  the single largest kernel task in this repo. Parity gate: `evidence/`
  fingerprint of first 8 logits on 64 positions with `tools/deep2_q5_decode_check`.

## P0/P1 — Gated DeltaNet fused decode (upstream `kernels/r9k_gdn.hip`, 40 KB)

One kernel does conv update + gating + recurrence + norm for hybrid/SSM layers.
Deep2 already has `src/deep2/NemotronHMamba2*.hpp` (Mamba2 arm, SSM step) and
`SsmCertProbe.hpp` — fusion there is a pure win if the recurrence is
row-tile-friendly on Vulkan. GDN state page per request under speculative
decoding maps onto `MedusaDecoder` + `K2KVCache` slots. Gate:
`tools/cmp_block0.py` + `SsmCertProbe` receipts.

## P1 — Speculative decoding (upstream `notes/release-v0.3.2.md`, MTP + DFlash2)

`src/deep2/MedusaDecoder.hpp` + `src/speculative/` already exist; upstream
contributes the int6 embedding-table-in-pinned-memory drafter trick and
acceptance measurement methodology (their HumanEval/GSM8K pairs). Gate:
tokens-per-draft vs. `throughput_baseline.json` on 64/128/256 position probes.

## P1 — Paged attention (upstream `kernels/r9k_attn.hip`, `r9k_qsa.hip`, `r9k_qsa_score.hip`)

Deep2's K-caches (`KVCache.h`, `KVCache_GQA.h`, `ToroidalKVCache`,
`SlidingWindowEngine`, `CompressedKVCache`) can absorb the block-table walk
and the indexer/sparse-query kernel. Long-context gate: 32k prompt TTFT at
`docs/phase5_win32ide_integration.md` acceptance line.

## P1 — P2P communication (upstream `kernels/r9k_hc.hip`, `r9k_hc_f8.hip`, `r9k_ar*.hip`, `r9k_transpose.hip`)

PCIe P2P all-reduce/all-gather incl. compressed 4/6-bit; relevant to
`src/deep2/K2GpuStreamCopy.hpp`, `DualGpuMirrorManager`, `ExchangeMirror`,
`HostExchangeDiscover`. Deep2's heterogeneous pairing (R9700 + 7800 XT) is
exactly where upstream says nothing — expect to need a lane-width tracer.

## P1 — Hyper-connection decode GEMMs (`kernels/r9k_hc_f8.hip`, r0.3.2 default)

fp8 weight copies at decode widths, bf16 WMMA on activations, bf16 freed after
quantization (+14% KV tokens at TP4). Maps to Deep2 dense decode on
`rawrxd_transformer*.cpp` once an fp8 WMMA/Vulkan path exists.

## Validation & measurement culture (upstream `tests/`, `bench/`, `profiling/`, `ablation/`, `notes/`)

Their gate set — full 1,319-question GSM8K with paired McNemar per release,
HumanEval, strict overload soak, 25-min mixed-length soak, multi-rank comms
tests, per-kernel unit gates — is the right template for Deep2's
`tools/verify_e2e_cert.py`, `tools/deep2_parity_trace.cpp` and the 150 TPS
acceptance target recorded in `docs/status/`. Adopt: (1) keep every perf claim
tied to an `evidence/` receipt; (2) benchmark on their Qwen Flash-Next shapes
only as cross-project sanity, never as Deep2 gates.

## Hard blockers to keep documented

1. Upstream dual-card configs assume ~120 GB host RAM; Deep2 host is 64 GB —
   host-memory expert streaming only viable per-layer subset.
2. Upstream is Linux/Docker/ROCm 10 only.
3. Benchmarks are matched R9700 pairs; Deep2 is heterogeneous.
4. The developer's claims (219 tok/s etc.) are unverified by us and are not
   Deep2 acceptance gates.
