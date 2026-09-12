# DEEP2_LINK15_NODEP_SOURCE_20260912

Source-only, dependency-free C linking layer for the remaining Deep2 production joins after the sealed TARGET64 correctness regression.

## Boundary

This drop does **not** replace the real kernels or manufacture runtime authority. It supplies:

- a stable C ABI for 15 production joins;
- hard ordering/dependency guards;
- an authoritative full-model TPS precondition guard;
- a deliberate rule that this layer can never mint `PROMOTE=1`;
- an opaque adapter so existing Deep2/SsVk/D2DeviceIo code can bind without importing Vulkan/ROCm/llama.cpp/Ollama headers into this layer;
- a deterministic self-test.

## Top 15 linking pieces

1. `FULL_MODEL_TPS_AUTHORITY` — seal baseline timing authority before optimization changes.
2. `UNIVERSAL_TILED_QUANT` — one tiled operator contract across supported quant codecs.
3. `DIRECT_PACKED_Q2K` — bind dense Q2_K batch-1 decode directly to packed-weight execution.
4. `PERSISTENT_DEVICE_RESIDENCY` — keep resident target weights/arenas out of the steady RAM→VRAM loop.
5. `D2DEVICEIO_TO_SSVK` — bind exact model ranges from product I/O into the native GPU executor.
6. `EXACT_RANGE_PRODUCT_BIND` — turn `(shard, offset, bytes, codec, shape)` references into executable tensor views.
7. `DEVICE_KV` — persistent device-side KV ownership and append/read semantics.
8. `FUSED_ATTN_PATH` — link norm/QKV/RoPE/KV/attention/residual without host tensor processing.
9. `FUSED_FFN_PATH` — link dense/MoE gate-up-activation-down/residual through native quant kernels.
10. `TILED_LMHEAD_DEVICE_REDUCE` — tiled vocabulary projection plus device-side max/top-k reduction.
11. `NATIVE_SAMPLER_COMMIT` — sampler consumes compact GPU result and commits the next token in Deep2.
12. `PERSISTENT_EXEC_GRAPH` — no per-token descriptor/pipeline/allocation reconstruction.
13. `REAL_DUAL_GPU_ARITHMETIC` — both GPUs execute useful arithmetic for the same decode path, with measured reductions.
14. `BOUNDED_64GB_STREAMING` — exact-range streaming path for models that cannot remain fully resident, with bounded arenas.
15. `UNIFIED_EXECUTOR` — converge correctness, residency, streaming, quant, dual-GPU and token commit onto one production executor.

The speculative/sweep-amortization design is intentionally **post-baseline** and not counted as a required link here.

## Authority law

`D2_LINK_01_TPS_AUTHORITY` can pass only if all of these are supplied by the existing runtime:

- TARGET64 sealed;
- full-model real decode;
- at least 64 generated tokens;
- zero sealed-logits reuse;
- zero synthetic logits;
- no device loss;
- warm-up excluded;
- non-zero wall time.

Only then does this linking layer set `D2_AUTH_FULL_MODEL_TPS`.

`D2_AUTH_PROMOTE` is never set by this drop.

## Bind model

Each real production component binds through:

```c
int my_link(void *user, D2LinkContext *ctx, D2LinkEvidence *out);
```

or through the opaque `D2AdapterThunk` wrapper in `d2_link15_adapter.h`.

The layer contains no Vulkan, D3D12, CUDA, ROCm, llama.cpp or Ollama dependency.

## Build

MSVC x64:

```bat
build_msvc.bat
```

Portable smoke check with a C compiler:

```sh
cc -std=c11 -O2 -Iinclude src/d2_link15.c src/d2_link15_default_adapters.c src/selftest.c -o d2_link15_selftest
```
