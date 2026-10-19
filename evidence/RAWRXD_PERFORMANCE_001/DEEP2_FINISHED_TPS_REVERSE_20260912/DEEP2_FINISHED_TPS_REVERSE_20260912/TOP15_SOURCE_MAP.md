# Finished-Deep2 12–25 TPS: top-15 source map

This list is ordered by impact on dense single-sequence decode. It assumes architecture/codec/shape are metadata-derived and the active cert binary remains untouched.

| # | Production source owner | Required behavior | Performance mechanism | Acceptance signal |
|---|---|---|---|---|
| 1 | `ops/d2_projection_tiled.*` | Fused quantized GEMV/GEMM reads Q2_K directly; no full FP16 dequant buffer | Cuts extra weight read/write traffic | `DEQUANT_MATERIALIZE_BYTES=0` |
| 2 | `quant/d2_q2k.*` | Vectorized Q2_K unpack + scale/min decode in-kernel | Makes BigDaddyG’s real codec first-class | `Q2_K_NATIVE=1` |
| 3 | `gpu/d2_pipeline_cache.*` | Persistent pipelines/descriptors/command templates | Removes per-token setup | `PIPELINE_CREATES_AFTER_WARMUP=0` |
| 4 | `residency/d2_residency.*` | Keep 69B Q2_K working set resident across 48 GB VRAM where possible | Avoids PCIe weight traffic | `H2D_WEIGHT_BYTES_PER_TOKEN≈0` |
| 5 | `gpu/d2_dual_gpu_place.*` | Place layers by measured bytes/BW, not equal layer count | Minimizes serial layer service time | `PLACEMENT_FROM_MEASURED_COST=1` |
| 6 | `gpu/d2_dual_gpu.*` | Minimize device boundaries; one-way activation handoff where possible | Cuts PCIe sync/transfer latency | `XGPU_BOUNDARIES<=1` for layer split |
| 7 | `residency/d2_exact_prefetch.*` | Exact-range N+1 prefetch with fixed double buffers for spill cases | Hides host/file latency | `PREFETCH_MISS_STALL_NS` measured and bounded |
| 8 | `runtime/d2_kv.*` | Persistent GPU KV with bounded format and no host round trip | Removes token-step copy stalls | `KV_HOST_READBACK_BYTES=0` |
| 9 | `ops/d2_attention_fused.*` | RMS/QKV/RoPE/KV/attention path stays device-side | Reduces dispatches and activation traffic | `ATTN_HOST_ROUNDTRIPS=0` |
| 10 | `ops/d2_dense_ffn_fused.*` | Gate/up activation fusion and tiled down projection | Cuts intermediate VRAM traffic | `FFN_INTERMEDIATE_MATERIALIZE=0/BOUNDED` |
| 11 | `ops/d2_moe_expert.*` | For MoE models, fetch/execute only router-selected expert ranges | Keeps non-BigDaddyG models sparse in bytes touched | `UNSELECTED_EXPERT_WEIGHT_BYTES=0` |
| 12 | `ops/d2_lm_head.*` | Reuse tiled projection engine; device-side partial max/top-k | Avoids full-logit host readback | `FULL_LOGITS_READBACK_BYTES=0` |
| 13 | `text/d2_sampler.*` | Native sampler consumes compact device result | Removes vocab-sized CPU boundary | `SAMPLER_EXTERNAL_DEPS=0` |
| 14 | `runtime/d2_arena.*` | Preallocate activation/KV/dequant/router/transfer arenas | Eliminates allocator jitter | `STEADY_STATE_HOST_ALLOCATIONS=0`, `STEADY_STATE_DEVICE_ALLOCATIONS=0` |
| 15 | `perf/d2_stage_telemetry.*` | Per-op bytes/ns counters + 50 ms/token gate | Converts projections into attributable evidence | `FULL_MODEL_TPS_AUTHORITY` minted only by cert harness |

## Projection interpretation

For touched weight bytes `W` and target TPS `T`, the minimum useful weight bandwidth is `W*T`. With `W=25 GB/token`: 12 TPS needs 300 GB/s; 15 needs 375 GB/s; 20 needs 500 GB/s; 25 needs 625 GB/s. The 25-TPS point leaves essentially no room under a 640-GB/s peak for dequantization, KV, dispatch, synchronization, or output work, so it is a roofline case rather than a conservative sustained estimate.

For layer sharding, do **not** add the two GPUs’ advertised bandwidths as though a single autoregressive token can consume both independently. Dependent transformer layers serialize. Tensor-parallel kernels may overlap work across devices but then pay cross-device reduction/synchronization costs. Dual GPU is therefore primarily a capacity/residency win until measured token latency proves otherwise.
