# RawrXD / Deep2 — Strata 12-Gate Integration: Final Matrix

**Directive:** `RAWRXD_DEEP2_STRATA_12_GATE_EXECUTION`
**Date:** 2026-10-13 · **Hardware:** AMD Radeon AI PRO R9700 (32 GB, device 0) + AMD Radeon RX 7800 XT (16 GB, device 4), Ryzen 7 7800X3D, 64 GB DDR4, Vulkan SDK 1.4.357.0, MSVC 19.44
**Models used:** `D:\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf` (MoE: deepseek2, 27 blocks, 64 experts, 6 routed + 2 shared, 9.9 GB), `D:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` (dense llama, 22 blocks)
**Rules applied:** native source only, no new dependencies, no stubs/simulated results, no silent fallback, BLOCKED reported instead of invented PASS, model-load/transfer costs included in measurements.

## Gate results

| Gate | Requirement | Status | Measured evidence |
|------|-------------|--------|-------------------|
| S01 | Native MoE expert residency manager; real placement/eviction traces | **PASS** | `StrataExpertResidency.hpp` ledger wired into `OpMoEExecute`; 28,677 timestamped observations on DeepSeek-V2-Lite, 1,221 evictions attributed by Hit→Miss transition of the same slice; receipt `strata_bench_deepseek_strata_lru.json` |
| S02 | VRAM expert cache; measured hit/miss; correct outputs | **PASS** | Backend device-local cache (`EnsureQuantWeight`) observed: hits 25,265 / misses 3,727 (hit rate 0.8714) at default budget; 21,700/4,876 (0.8165) at a 4 GiB cap with 2,831 real evictions; budget respected exactly (`device_bytes_live=4,293,394,976` ≤ 4 GiB); outputs token-identical across all configs, 0 non-finite logits, 0 CPU fallback |
| S03 | Adaptive expert prefetch; overlaps compute, no stale reads | **PARTIAL** | Real prefetch implemented (`PrefetchQuantWeight`, down-bank at block entry): 1,580 uploads under 4 GiB cap, 0 stale reads (fingerprint-validated cache), outputs identical, budget respected. No measurable speedup (decode 1.24 vs 1.27 TPS LRU) because the upload path is synchronous (`CopyHostToBuffer` + fence); true compute overlap needs an async transfer queue — recorded as a defect, gate not claimed |
| S04 | PCIe transfer calibration; bandwidth, latency, bytes | **PASS** | Measured in every receipt: MoE run moved 7,757,864,640 B host→device + 234,823,680 B device→host; staging bandwidth H2D 17.53 GB/s, D2H 22.70 GB/s (256 MiB × 5 iterations, pinned host buffers). Link-geometry registry scan returns empty on this host (disclosed); the transfer measurement is the substantive evidence |
| S05 | GPU/CPU expert scheduling; routing across CPU, R9700, RX 7800 XT | **PARTIAL** | Per-device routing **PASS**: identical 16-token prompt / 8 generated tokens produce token-identical streams on CPU-pinned, R9700 (`--device 0`, 2.11 TPS under load) and RX 7800 XT (`--device 4`, 4.18 TPS, 3,720 dispatches, 0 fallback). Concurrent multi-GPU execution **not implemented** (one device context per process) — open defect |
| S06 | INT8 KV-cache storage; parity, memory savings, long-context | **PASS** | `StrataInt8KVCache.hpp` (Q8_0, ggml block semantics) wired behind opt-in: tinyllama GPU decode with INT8 KV vs FP32 = **24/24 identical tokens**; live savings 71.88% (1,419,264 vs 5,046,272 B); synthetic selftest all widths PASS (max err 0.0157 ≤ amax/127); 1M-row store PASS (380,626 rows/s); MLA latent cache deliberately untouched |
| S07 | Native speculative decoding; verified acceptance; distribution correctness | **BLOCKED (speedup)** | Machinery real: prompt-lookup drafting + greedy target verification; plain vs K=4 vs K=8 produce **identical 32-token streams** (distribution preserved by construction); full acceptance accounting (proposed/accepted/rejected/chains). Acceptance 0% on tested workloads (target does not copy the drafted continuation); throughput **slower**: 2.82 TPS (K=4) and 2.23 TPS (K=8) vs 3.50 baseline → speedup 0.72×/0.57×. Root cause: the executor runs one token per forward, so verifying k draft tokens costs k forwards; speculation cannot pay off without batched multi-token prefill. Reported BLOCKED rather than claimed |
| S08 | Expert hotness prediction; improved hit rate/throughput vs baseline | **FAIL (improvement not achieved)** | Hotness policy (aged dispatch-count eviction) implemented and measured head-to-head with LRU under real pressure: hotness hit rate 0.7774 / decode 1.06 TPS vs LRU 0.8165 / 1.27 TPS — hotness is **worse** (the router has strong recency locality). Default remains LRU; the negative result is the certified outcome |
| S09 | Persistent streaming pipeline; no avoidable stalls/deadlocks | **PARTIAL** | Zero deadlocks or sync faults across all runs; MoE expert dots are batched (Begin/EndQuantDotBatch: 3 submissions per block instead of 12). Measured: dense path 158 submits/token, MoE path ~292 submits/token, `wait_ms ≈ kernel_ms` (host blocked on the fence for essentially all kernel time); `submit_ms` only 0.9% — the remaining stall is architectural (one submit+fence per dot on the dense path). Optimization recorded as a defect |
| S10 | Prefill/decode instrumentation: TTFT, prefill TPS, decode TPS, aggregate TPS | **PASS** | New native trace-free harness `tools/deep2_strata_bench.cpp` (+ build script) reports all four metrics separately with p50/p95 per-token latency, dispatch counters, fallback reason, non-finite count, and a machine-readable JSON receipt per run. Example (DeepSeek-V2-Lite): TTFT 80,212 ms, prefill 0.91 TPS, decode 1.15 TPS, aggregate 0.98 TPS |
| S11 | Quality/context certification 4K→32K→128K→512K→1M | **PARTIAL** | KV subsystem certified to 1M tokens (synthetic store: 71.88% savings, readback parity PASS; arithmetic 30.04 GiB INT8 vs 106.81 GiB FP32 per 1M context at 28 layers × 512 width). Model-level context runs **BLOCKED**: the executor has no batched prefill, so a 4K-token prompt costs ≈ 21 min at the measured 0.91–3.2 prefill TPS (arithmetic disclosed); token-level output quality at reachable contexts is certified by the existing Gate 5/6 parity harnesses |
| S12 | End-to-end performance certification, ≥150 TPS decode | **FAIL (floor not met)** | Measured real decode: tinyllama Q4_K_M R9700 3.84–4.35 TPS (cold/warm), RX 7800 XT 4.18 TPS, CPU 1.36–1.42 TPS; DeepSeek-V2-Lite MoE 1.15–1.29 TPS. The 150 TPS floor is **not met** (35–130× gap). Measured blockers: per-token sequential executor, 158–292 submissions/token, host fence-wait ≈ kernel time. Reported as FAIL with the full trail, per the rule against substituting aggregate/single-stream or omitting overhead |

**Final: S01, S02, S04, S06, S10 PASS · S03, S05, S09, S11 PARTIAL · S08 FAIL (improvement) · S07 BLOCKED (architecture) · S12 FAIL (floor)**

## Reproduction commands

```
tools\build_deep2_strata_bench.bat                          # build the harness
tools\deep2_strata_bench.exe --kv-selftest 200              # S06 synthetic
tools\deep2_strata_bench.exe --kv-context-test 1000000      # S11 KV store
tools\deep2_strata_bench.exe --model <gguf> --prefill 32 --generate 16 --gpu [--strata|--strata-prefetch|--strata-hotness] [--device 0|4] [--int8kv] [--spec N --draft-k K --repeat-prompt]
set RR_WEIGHT_CACHE_MAX_BYTES=4294967296                    # 4 GiB cache pressure
```

## New source (this program)

- `src/deep2/StrataExpertResidency.hpp` — expert residency ledger (placement/eviction traces, hotness counters)
- `src/deep2/StrataInt8KVCache.hpp` — Q8_0 INT8 KV tier with parity/error accounting
- `src/deep2/quant_dot_dispatch.{hpp,cpp}` — `IsWeightResident`, `PrefetchWeight`, `SetCachePolicy`, `GetCacheStats`, `SetPreferredDevice` (all additive)
- `include/vulkan_compute.h`, `src/vulkan_compute.cpp` — eviction/prefetch counters, hotness policy (`RR_WEIGHT_CACHE_POLICY`), residency query/prefetch primitives; timestamp-valid-bits sourced from queue-family properties (SDK layout fix that unblocked the tree build)
- `src/deep2/runtime_graph_executor.{hpp,cpp}` — Strata observation/prefetch/INT8-KV wiring in `OpMoEExecute`/`OpAttention`, all opt-in, default-off
- `tools/deep2_strata_bench.cpp`, `tools/build_deep2_strata_bench.bat` — S10/S12 certification harness

## Regression evidence

- `tools\deep2_parity_trace.exe` rebuilt after all shared-TU changes: GENSTREAM bit-identical to the pre-change certification run (`13 8.292262 29899 … 29871 15.749612`), gpu_calls=2635, cpu_calls=0, fallback=<none>
- All Strata runs: `cpu_calls` 0 or `force_cpu`-disclosed, `fallback=<none>`, `nonfinite_logits=0`
- Q2_K model honestly reports its GPU kernel gap (1764 CPU calls, recorded fallback reason) rather than silently mixing paths
