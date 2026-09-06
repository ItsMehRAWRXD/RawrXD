# STREAMER / MULTIGPU disposition (2026-09-06)

## Claim boundary (hard)

```text
RAWRXD_DEEP2_STREAMER=CERTIFIED
  on dual-discrete-GPU host
  with AVX-512 / CPU-native decode active
  and no GPU compute participation
```

Do **not** describe current TPS as dual-GPU compute.

```text
DUAL_GPU_HOST        = YES
DUAL_GPU_COMPUTE     = NO
DEEP2 STREAMER       = CERTIFIED 10/10
OLLAMA               = NOT INVOLVED
```

## Certified path (actual)

```text
GGUF → Deep2 streamer → AVX-512 decode → CPU / system RAM → tokens
```

## Host topology (present)

```text
Ryzen 7 7800X3D
  ├─ 64 GB DDR5          ← staging / mmap / IDE only (not tensor tier)
  ├─ Radeon AI PRO R9700 — 32 GB VRAM (compute primary)
  └─ Radeon RX 7800 XT     (draft / secondary / independent streams)
```

Both GPUs are discrete. This machine is **not** UMA. UMA remains a portable backend for other hosts.

Memory policy: **VRAM-first, PCIe-minimal, RAM-as-staging-only**.

## Immutable CPU baseline (STREAMER_CERT_001 live)

| Model | BENCH_64 decode | BENCH_64 E2E |
|-------|----------------:|-------------:|
| TinyLlama 1.1B Q4_K_M (prior) | 8.52 | 8.35 |
| TinyLlama 1.1B Q4_K_M (now) | **12.27** | **12.09** (~+44%) |
| Phi-3-mini Q8_0 | **2.61** | **2.57** |

## Next gate (do not skip to MULTIGPU)

`GPU_COUNT=3` is the 7800X3D iGPU plus two discrete cards. That is host topology, not compute.

```text
CURRENT
CPU_NATIVE 10/10
      │
      ▼
STREAMER_GPU_SOLO_001   R9700 real GGUF decode (enumerate 3, open 1)
      │
      ▼
STREAMER_GPU_SOLO_002   7800XT real GGUF decode
      │
      ▼
STREAMER_SPECULATIVE_001
      │
      ▼
STREAMER_MULTIGPU_001
      │
      ▼
STREAMER_AUTOTUNE_001
```

Do **not** jump to speculative or layer-shard until R9700 solo can execute the target model.

Stable CPU reference is **MULTI15 decode ~12.1–12.6 tok/s**. Do not replace the frozen **8.52 BENCH_64** baseline with the unstable 3.42 rerun; compare lane-to-identical-lane only.

Vulkan: discover all physical devices, `vkCreateDevice` only on the R9700. iGPU and 7800 XT stay DETECTED/UNUSED.



## Fastest-path hierarchy (after solo gates)

```text
Model fits fully in R9700 32 GB?
         /                    \
       YES                     NO
        │                       │
        ▼                       ▼
 FAST_SINGLE / SPEC          FAST_MULTI (layer shard)
 R9700 = full target         R9700 = majority layers + KV
 7800  = speculative draft   7800  = contiguous mid block + KV
   OR idle                   one activation transfer each way
```

### Do NOT

- Alternate GPUs every layer (PCIe hammer)
- Split 50/50 by marketing FLOPS
- Put system RAM in the decode hot path (GPU→RAM→GPU)
- Claim dual-GPU compute before STREAMER_MULTIGPU_001

### Do

- Keep weights + KV resident on the GPU that owns the layer
- Calibrate split from measured GEMV/GEMM/attention/PCIe benches
- Overlap compute with tiny pinned transfer rings (2–16 MB slots)
- Fuse dequant+GEMV and keep PCIe hops ≤ 2 per token for sharded mode

### Speculative-first (preferred when target fits R9700)

```text
7800 XT: draft K candidates (adaptive K=2..8)
   tiny PCIe payload (token IDs / control)
R9700: verify batch in one target pass → accept/reject
```

Cards run asynchronously; no shared weights; no per-layer sync.

### MAX_THROUGHPUT (multi-agent)

```text
request A → R9700 entirely
request B → 7800 XT entirely
CPU → orchestration / overflow
```

Zero inter-GPU sync — often best **aggregate** TPS.

## Backend hierarchy (permanent)

```text
validated MULTIGPU/SPEC → validated single GPU → UMA → CPU native fail-safe
```

GPU unhealthy ⇒ CPU native. Never crash because a GPU exists.

## STREAMER_MULTIGPU_001 lanes

| Lane | R9700 | 7800 XT | Purpose |
|------|-------|---------|---------|
| A | full model | off | single-card baseline |
| B | off | full model | secondary baseline |
| C | target | speculative draft | max single-stream candidate |
| D | layers A | layers B | model-sharded dual GPU |

Measure: decode TPS, E2E TPS, TTFT, PCIe bytes/token, util, VRAM/KV residency, speculative accept rate.

PASS only if real GGUF streamer path drives the bridge/spec path with both adapters doing real work, valid tokens, no silent CPU substitution for claimed GPU layers, witnesses honest, CPU fallback still works.

## Required witnesses

Current (CPU floor):

```text
DEEP2_COMPUTE_BACKEND=CPU_NATIVE
DEEP2_GPU_COUNT=<detected>
DEEP2_GPU_COMPUTE_ACTIVE=0
DEEP2_STREAMER_CERT=10/10
DUAL_GPU_HOST=YES
DUAL_GPU_COMPUTE=NO
```

Lane C (spec):

```text
DEEP2_COMPUTE_BACKEND=SPECULATIVE_DUAL
DEEP2_PRIMARY_GPU=R9700
DEEP2_SECONDARY_GPU=RX7800XT
DEEP2_GPU_COMPUTE_ACTIVE=2
DEEP2_SPEC_K=<k>
DEEP2_SPEC_ACCEPT_RATE=<rate>
```

Lane D (shard):

```text
DEEP2_COMPUTE_BACKEND=MULTIGPU_SHARD
DEEP2_LAYER_SPLIT=<actual>
DEEP2_GPU_TRANSFER_COUNT=<per token>
DEEP2_GPU_COMPUTE_ACTIVE=2
```

## Blockers

- Dual-AMD Vulkan ICD: unsafe — leave blocked until a non-ICD or validated ICD path exists.
- `Deep2MultiGpuBridge`: exists; not on streamer GGUF decode path.
- Speculative draft path: not yet implemented on streamer_cert.
