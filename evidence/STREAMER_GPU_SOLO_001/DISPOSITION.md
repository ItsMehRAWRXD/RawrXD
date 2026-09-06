# STREAMER_GPU_SOLO_001 — disposition (2026-09-06)

## Gate order (locked)

```text
CPU_NATIVE CERTIFIED 10/10
        │
        ▼
STREAMER_GPU_SOLO_001   ← R9700 only (this gate)
        │
        ▼
STREAMER_GPU_SOLO_002   ← RX 7800 XT only
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

Do **not** open MULTIGPU / speculative until SOLO_001 proves real GGUF decode on R9700.

## Certified CPU floor (immutable reference)

```text
SYSTEM_RAM=64GB
DEEP2_COMPUTE_BACKEND=CPU_NATIVE
DEEP2_GPU_COMPUTE_ACTIVE=0
DUAL_GPU_HOST=YES
DUAL_GPU_COMPUTE=NO
RAWRXD_DEEP2_STREAMER=CERTIFIED 10/10

TinyLlama Q4_K_M multi15 decode ≈ 12.1–12.6 tok/s   (STABLE)
Phi-3 Q8_0 multi15/BENCH ≈ 2.6–3.0 tok/s
BENCH_64 frozen baseline = 8.52 tok/s (do NOT replace with 3.42)
```

`DEEP2_GPU_COUNT=3` = iGPU + R9700 + 7800 XT (detect-all / open-one).

## SOLO_001 contract

```text
Deep2 GGUF → R9700 only → real GEMV on selected VkDevice → sample → token
CPU remains fail-safe if Vulkan init or GPU forward fails.
```

### Required witnesses

```text
DEEP2_COMPUTE_BACKEND=GPU
DEEP2_GPU_SELECTED=R9700   (substring match on Vk device name)
DEEP2_GPU_COMPUTE_ACTIVE=1
DEEP2_CPU_FALLBACK_USED=0
DEEP2_REAL_WEIGHT_LAYERS=<count that hit GPU GEMV>
DEEP2_REAL_GPU_FORWARD=1
```

### Device policy

```text
enumerate adapters: OK (3)
initialize VkDevice: EXACTLY ONE (R9700 preferred)
7800 XT: DETECTED / UNUSED
iGPU:    DETECTED / UNUSED
```

Set `DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1=1`. Prefer name filter over first-discrete.

## Benchmark matrix (same prompt / token counts)

| Model | CPU multi15 decode | R9700 |
|-------|-------------------:|------:|
| TinyLlama Q4_K_M | 12.1–12.6 | TBD |
| Phi-3 Q8_0 | ~2.6–3.0 | TBD |
