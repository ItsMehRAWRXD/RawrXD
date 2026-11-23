# Native Universal Tensor Residency

## Design contract

RawrXD does not rewrite a model's GGUF payload to obtain runtime memory savings. GGUF remains the interchange/source format. The Deep2 runtime keeps source tensors paged, optionally admits profitable private compressed representations into bounded residency caches, and materializes only requested inference tiles.

The runtime must never select an encoding unless its decoder is implemented and the required error contract is satisfied. Unsupported GGUF type IDs fail closed; no byte stride or bit layout is inferred from a name.

## Storage paths

| Source type | Resident representation | Inference materialization |
|---|---|---|
| F32 | Bounded chunked adaptive representation (lossless RLE/LZ4 by default; optional error-bounded F16/BF16) | Requested F32 chunk/tile |
| F16, BF16, F64 | Original encoded bytes in the bounded ROM pager; optional lossless RLE/LZ4 byte residency when a chunk wins | Requested F32 tile |
| Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_1 | Canonical GGML blocks; optional lossless RLE byte residency only when smaller | Requested block-aligned F32 tile |
| Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K | Canonical GGML super-blocks; optional lossless RLE byte residency only when smaller | Requested 256-value-block-aligned F32 tile |
| I8, I16, I32, I64 | Original exact integer bytes; optional lossless RLE byte residency when smaller | Requested F32 tile for current floating-point inference kernels |

The encoded-byte residency cache uses lossless RLE/LZ4 chunks and is deliberately lossless: a quantized payload is never quantized a second time merely to make it smaller. Chunks that do not produce a net saving stay on the source pager path. After successful cache admission, corresponding unleased source pages are evicted to avoid retaining a duplicate raw copy. Runtime admission evaluates the complete tensor (subject to the hard residency budget), not only its first chunk, so a mixed tensor with an incompressible prefix and compressible remainder can still be retained when its aggregate representation wins.

Admission failures are classified: source-reader failures and unexpected runtime/allocation exceptions remain retryable; a typed deterministic no-win or residency-budget rejection is memoized as a raw-pager fallback. This prevents repeated scans of tensors already proven not to fit while avoiding permanent fallback decisions after transient failures. The cache regression tests cover both classes.

## Configuration

- `DEEP2_ROM_CACHE_BYTES`: source-page cache capacity.
- `DEEP2_F32_MAX_ABS_ERROR`: optional finite, nonnegative absolute error allowance for F32-to-F16/BF16 private residency. Default is `0` (lossless only). This setting does not alter GGUF files.
- F32 and encoded-byte residency budgets are selected from currently available physical RAM at engine initialization (F32: one eighth, capped at 2 GiB; encoded bytes: one thirty-second, capped at 512 MiB, with conservative minimums).
- `DEEP2_F32_RESIDENCY_MB` and `DEEP2_ENCODED_RESIDENCY_MB` override the respective budgets in MiB. Invalid or overflowing values are ignored in favor of the computed default.
- `DEEP2_F32_CACHE_BYTES` and `DEEP2_ENCODED_CACHE_BYTES` provide exact byte-count overrides and take precedence over the MiB settings. Invalid values fail initialization rather than silently selecting an unexpected memory budget.

The engine exposes `GetTensorResidencySnapshot()` for compressed/logical bytes, source-pager resident bytes and capacity, persistent device-local packed-weight bytes and budget, tensor counts, cache hits/misses, decoded bytes and evictions. Total tracked residency includes host compressed storage, source-pager resident bytes, and persistent GPU tile buffers.

## Current kernel integration

ROM F32, floating and supported quantized 2-D projection weights use bounded row tiles. F32 tiles admitted as uniform F16/BF16 are exported in compact form; native GGUF F16/BF16 and Q8_0 tiles are read directly from the ROM. These formats are uploaded compactly to device-local Vulkan storage and consumed by a typed GEMV shader. Other quantized formats still use the bounded CPU dequantize-to-F32 fallback.

## Deliberate limitations / remaining certification

- IQ-family, TQ-family, MXFP4, NVFP4, and other GGUF formats not listed above remain unsupported by this Deep2 ROM decoder. The loader rejects unknown type IDs rather than guessing.
- GPU-side RLE/LZ4 decode and direct Q2_K/Q3_K/Q4_K/Q5_K/Q6_K/Q8_K shader kernels remain unimplemented. Those formats still use CPU block decode for unsupported operators.
- Every production operator must be audited for use of the tiled ROM path; this document does not claim universal operator coverage.
- CI must pass on Windows and Linux, followed by reference-logit parity, peak host/VRAM measurement, and multi-agent stress tests before release certification.


## Vulkan compact-weight execution and residency

The standalone ROM GEMV path now has a typed packed-weight shader for:
- F16 and BF16 weights, including F32 source tensors admitted to exact or explicitly error-bounded 16-bit residency.
- Native GGUF Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, and Q8_1 fixed blocks (32 values per block), plus Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, and Q8_K blocks (256 values per block).

The shader consumes those compact bytes directly and accumulates products in F32. Q4/Q5/Q8 and K-quant blocks are decoded from their GGUF byte layouts; a CPU mirror regression compares the shader's nibble, bit-plane, scale/minimum, signed-byte, and F16/F32-scale interpretation with the repository's NativeKQuant and fixed-block dequantizers across adjacent blocks. Other GGUF quant formats continue through the bounded CPU F32-tile fallback.

Compact weight tiles are uploaded through a completion-backed staging transfer into device-local Vulkan buffers. Transfer-to-compute and compute-to-host memory barriers make the dataflow explicit. Vulkan copy sizes are padded to the required four-byte alignment without changing logical tensor geometry. The staging resources are released only after a successful fence wait (or a safe device-idle recovery); uncertain completion fails closed.

An LRU device-local weight-buffer cache retains immutable packed tiles across GEMV calls. Cache identity includes the device, shard/tensor identity, tile range, source type, and F32-derived packed encoding. DEEP2_GPU_WEIGHT_RESIDENCY_MB sets its byte budget in MiB; the default is capped at 512 MiB and scales against reported device-local memory. Shutdown waits for devices and destroys cached buffers before destroying their owning devices. GetTensorResidencySnapshot() reports the GPU cache budget and resident bytes.

This is persistent compressed tile residency, not yet a full-model VRAM cache: only tiles actually requested by the ROM GEMV path are admitted, and eviction is LRU. RLE/LZ4 streams are still decoded on the CPU before unsupported operators run. The F32 reference shader remains available as a correctness fallback.


## Compact F16/BF16 range export for device consumers

`ChunkedF32Storage::ExportUniform16BitRange` and `TensorResidencyCache::ExportUniform16BitRange` expose a selected range of cached F16/BF16 payloads without first decoding them to F32. The requested logical range may begin or end inside a chunk and may span multiple chunks, provided all intersecting chunks share the same F16 or BF16 encoding. Partial chunk slices are copied directly from compact payloads; mixed codecs, raw chunks, RLE, and LZ4 are rejected without returning ambiguous bytes. The cache wrapper pins the entry while exporting so concurrent LRU eviction cannot invalidate the source.

This is the required host-side handoff primitive for a GPU kernel that consumes compressed F16/BF16 weights directly. A regression test verifies the exported bytes round-trip to the exact source values for an F16-exact tensor, rejects unaligned ranges, and confirms the reader pin is released.

**Important boundary:** the standalone ROM Vulkan GEMV now connects compact F16/BF16/Q8_0 payloads to the packed shader and retains packed tiles in a bounded device-local cache. This does not make every Deep2 operator consume compressed data. Quantized GGUF RLE/LZ4 payloads still require a separate device decoder/kernel contract; their encoded representation must not be mistaken for F16/BF16/Q8_0.


## Production Deep2 GPU path: packed F16/BF16 GEMV

The production Deep2 path under ~dev/rawrxd/src/deep2 has a separate native Vulkan QGEMV implementation (deep2_qgemv.comp) that accepts GGML F16 (type 1) and BF16 (type 30) weight views alongside its supported packed GGUF quant types. The shader reads 16-bit weights from the device buffer, converts each value in the shader, and accumulates the dot product in F32.

The Vulkan runtime now enables this preparation by default when Vulkan is initialized. Its default absolute-error budget is **zero**, so only bit-exact F16/BF16 conversions are accepted; tensors that cannot be represented uniformly and exactly stay on the original F32 path. Set DEEP2_F32_GPU_COMPRESSION=0 to disable it. A nonzero DEEP2_F32_MAX_ABS_ERROR explicitly opts into bounded lossy conversion. The default packed-host budget is 512 MiB and can be changed with DEEP2_F32_GPU_COMPRESSED_BUDGET_MB.

The resident forward-layer GEMV dispatch now checks for a uniform packed view before calling EnsureF32. When available, it submits the 16-bit payload through DispatchGemvQuant (or the typed prefetch lane) so the Vulkan weight cache receives half-width bytes and the QGEMV shader accumulates in F32. Counters distinguish F16 and BF16 GEMV submissions and account submitted packed-weight bytes. The existing single-GPU and dual-GPU row-split view builder also exposes the same packed representation.

**Scope and memory accounting:** this is a real device-side storage reduction for the F32 weights that qualify and are actually routed through the Vulkan QGEMV paths; it is not universal model compression. The original host F32 source remains available as the CPU fallback, so this path does not claim a 50% reduction in total host RAM. The separate standalone ROM Vulkan path documented above still uploads F32 tiles. Other operators, mixed-codec chunks, unsupported GGUF types, and nonuniform F32 tensors require additional integration or use their existing fallback. Release claims require Windows/Linux CI, numerical parity against the F32 reference, and measured per-device VRAM before/after receipts.


## Automatic F32 residency during model binding

The native Deep2 GGUF binding now evaluates every bound F32 tensor for compressed residency by default. The default precision budget is zero: exact F16/BF16 representations may be retained, and lossless RLE/LZ4 chunks are retained where they reduce storage. Chunks that do not produce a net saving are rejected rather than kept as raw duplicates. Matrix tensors use row-sized chunks for row-at-a-time GEMV; vectors use 4096-element chunks. A 512 MiB per-model compressed-storage budget bounds retained private payloads.

Controls:

- `RAWRXD_COMPRESS_F32=0` disables model-load F32 compression; `1` explicitly enables it.
- `RAWRXD_COMPRESS_F32_MAX_ABS_ERROR` sets an explicit nonnegative absolute-error tolerance. The default is 0.
- `RAWRXD_COMPRESS_F32_BUDGET_MB` changes the retained compressed-storage budget in MiB.

The Vulkan initialization step builds the fixed-stride GPU F16/BF16 payload directly from the mapped F32 source using the GPU-specific error budget. This is deliberately separate from adaptive CPU storage selection: a zero-heavy tensor may be stored as RLE in the CPU cache while still being converted to F16 for QGEMV, provided every element satisfies the configured error bound. The direct packer rejects non-finite values and F16 overflow, tries BF16 as the wider-exponent fallback, and does not allocate an intermediate full-size F32 vector. The intermediate CPU chunk object is released when a tensor is promoted to a GPU payload. Mixed or losslessly encoded RLE/LZ4 tensors that cannot be represented uniformly in F16/BF16 remain available to the CPU path and are never mislabeled as GPU F16/BF16. LinearW attempts the GPU route first and uses the chunked CPU GEMV only after GPU fallback, so model-load compression no longer disables Vulkan execution preemptively.

The WeightTensor builder uses the bounded streaming reader API and enforces the remaining model budget while building chunks. It does not create a second full-size F32 staging vector. Regression coverage verifies chunk-boundary reads, bounded admission, and budget rejection.

**Memory accounting caveat:** the GGUF file mapping remains the authoritative source and is retained for fallback. This change adds bounded compressed private storage; it does not yet unmap or replace the original file mapping, so a 50% reduction in total host working set is not claimed. The device-side F16/BF16 savings apply only to tensors promoted and submitted through supported Vulkan QGEMV paths. Measured process working-set and per-device VRAM receipts remain required.


## Lossless residency for already-quantized GGUF tensors

Model binding also evaluates non-F32 tensor payloads for lossless byte compression. The native `ChunkedByteStorage` retains independently encoded RLE/LZ4/raw chunks only when the complete tensor has a net storage win and fits the same per-model 512 MiB residency budget used by F32 private storage. The GGML wire type, block geometry, and source mapping remain unchanged. Set `RAWRXD_COMPRESS_QUANTIZED_BYTES=0` to disable this path.

For supported Vulkan QGEMV types (Q8_0, Q2_K, Q4_K, Q6_K), the resident forward path reconstructs only a bounded 256 KiB row tile from compressed byte chunks, then dispatches that original quantized block representation to the existing shader. Output-row offsets preserve the final matrix layout. Each immutable tile has a distinct cache key incorporating tensor identity, row window, and quant type; the cache fails closed on key/type/size mismatches. The path avoids fused-command lifetimes so a tile cannot be evicted while an unsubmitted command references it.

The CPU LinearW fallback uses the registered GGML block geometry and dequantizer to reconstruct one quantized row at a time into reusable scratch, then computes that row's dot product. It does not expand the full quantized matrix to F32. Quantized types not supported by the packed Vulkan shader can still use the CPU row path when a compressed byte backing exists.

**Remaining scope:** compressed-byte residency is attached to model-bound tensors. Selected-row embedding lookup, quantized RMSNorm reads, CPU LinearW, and supported non-fused Vulkan QGEMV (Q8_0, Q2_K, Q4_K, Q6_K) consume bounded decoded ranges. Other normalization/state tensors, every quantized GGML type on Vulkan, expert-prefetch/fused execution, and lazy tensor-loading paths still require dedicated integration. The source GGUF mapping remains available for fallback; this is not yet a claim that all mapped pages have been released or that process RSS has fallen by the compressed-byte ratio.


## Packed Q8_0 and persistent device-local tile cache

The gemv_packed16.comp shader now accepts encodings 3 through 14 for fixed-block Q4/Q5/Q8 and K-quant Q2_K/Q3_K/Q4_K/Q5_K/Q6_K/Q8_K. Fixed formats use 32-value blocks; K-quants use 256-value blocks and their native scale, minimum, nibble, and bit-plane layouts. The ROM path reads only the block-aligned byte range for the current row tile. The Vulkan GEMV preflight checks block geometry, element-index limits, byte-size overflow, and the device's maxStorageBufferRange.

F16, BF16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_1, Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K, and eligible F32-derived 16-bit tiles are uploaded in their compact byte representation to device-local storage. A per-device LRU cache retains those immutable buffers under DEEP2_GPU_WEIGHT_RESIDENCY_MB; uncacheable or over-budget tiles use an ephemeral device-local buffer and are released after synchronous dispatch. Pipeline objects are cached independently per VkDevice and destroyed before their device, avoiding cross-GPU pipeline reinitialization and stale handles.

CI now includes a CPU mirror of the packed Q4/Q5/Q8 and K-quant shader decoders against the canonical GGUF dequantizer, plus optional glslc compilation when the compiler is installed. The full native Vulkan engine build, shader validation on an SDK-equipped runner, GPU parity, device-cache stress/eviction, and measured host/VRAM savings remain release gates.


## K-quant direct packed GEMV

The packed Vulkan shader now has encodings for all six GGML K-quant formats. The ROM tile reader enforces 256-value row/block alignment and streams only the corresponding encoded block interval. The shader decodes Q2_K scale/minimum nibbles, Q3_K scale/high-mask bitplanes, Q4_K/Q5_K grouped scales and minima (including Q5 high bits), Q6_K low/high planes and signed group scales, and Q8_K F32 scale plus signed bytes. Accumulation remains F32.

The K-quant decoder implementation is mirrored from `NativeKQuant::DecodeBlock`; the expanded CPU regression checks the shader's byte-address calculations against that decoder for two adjacent blocks per format. This establishes CPU decoder agreement, not independent upstream GGML validation or GPU numerical parity. Shader compilation, Vulkan execution, full-model operator coverage, and memory/latency measurements remain required before release certification.
