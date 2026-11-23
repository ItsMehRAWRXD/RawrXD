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

The engine exposes `GetTensorResidencySnapshot()` for compressed/logical bytes, source-pager resident bytes and capacity, tensor counts, cache hits/misses, decoded bytes and evictions. The snapshot's total-resident value counts compressed cache bytes plus source-pager resident bytes once.

## Current kernel integration

ROM F32, floating and supported quantized 2-D projection weights use bounded row tiles. For Vulkan, each requested tile is decoded on the CPU, uploaded as F32, and dispatched through the existing Vulkan GEMV path. This avoids a full-matrix F32 allocation but is **not** GPU-native decompression.

## Deliberate limitations / remaining certification

- IQ-family, TQ-family, MXFP4, NVFP4, and other GGUF formats not listed above remain unsupported by this Deep2 ROM decoder. The loader rejects unknown type IDs rather than guessing.
- GPU-side decode kernels and persistent compressed GPU weight residency are not implemented by this change.
- Every production operator must be audited for use of the tiled ROM path; this document does not claim universal operator coverage.
- CI must pass on Windows and Linux, followed by reference-logit parity, peak host/VRAM measurement, and multi-agent stress tests before release certification.


## Vulkan tile staging lifecycle

The ROM Vulkan GEMV route still expands only the requested compressed/dequantized row tile on the CPU, then uploads/dispatches that bounded F32 tile. It does **not** yet perform RLE/LZ4/F16/BF16 decode inside a Vulkan shader or retain a compressed representation in VRAM. This distinction is intentional: the current shader contract consumes F32 storage buffers, so claiming GPU-native compressed residency would be inaccurate.

The synchronous GEMV path now explicitly unmaps each host-visible weight/input/output allocation before destroying its buffer and freeing its memory. The Vulkan buffer allocator also fails closed if binding or mapping fails and clears output handles on those failures. This fixes a per-tile mapped-memory lifetime defect in the current upload path; it does not change numerical behavior or establish GPU decompression parity.

The next GPU-residency milestone requires a separate shader contract that accepts the encoded chunk format and its metadata (encoding kind, compressed byte length, logical element count, and chunk boundaries), validates bounds before decode, and feeds decoded values directly into the compute operation. That work must preserve the existing F32 GEMV reference path until device-side decode has independent correctness and memory measurements.


## Compact F16/BF16 range export for device consumers

`ChunkedF32Storage::ExportUniform16BitRange` and `TensorResidencyCache::ExportUniform16BitRange` expose a selected range of cached F16/BF16 payloads without first decoding them to F32. The range must cover complete independently encoded chunks (the final range may end at tensor end), and every chunk must use the same 16-bit encoding. Partial chunks, mixed codecs, raw chunks, RLE, and LZ4 are rejected without returning ambiguous bytes. The cache wrapper pins the entry while exporting so concurrent LRU eviction cannot invalidate the source.

This is the required host-side handoff primitive for a GPU kernel that consumes compressed F16/BF16 weights directly. A regression test verifies the exported bytes round-trip to the exact source values for an F16-exact tensor, rejects unaligned ranges, and confirms the reader pin is released.

**Important boundary:** the current standalone Vulkan GEMV still consumes F32 tiles. This commit does not yet connect the compact export to a Vulkan descriptor or ship a compressed-weight GEMV shader. Until that kernel and independent GPU parity test exist, the runtime GPU-resident memory reduction is not certified. Quantized GGUF RLE/LZ4 payloads also still need an explicit device decoder/kernel contract; their encoded representation must not be mistaken for F16/BF16.


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

**Remaining scope:** compressed-byte residency is currently attached to model-bound tensors and selected supported quantized operators. Embedding lookup, all normalization/state tensors, every quantized GGML type on Vulkan, expert-prefetch/fused execution, and lazy tensor-loading paths still require dedicated integration. The source GGUF mapping remains available for fallback; this is not yet a claim that all mapped pages have been released or that process RSS has fallen by the compressed-byte ratio.
