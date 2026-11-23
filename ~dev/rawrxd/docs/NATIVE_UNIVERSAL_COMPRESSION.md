# Native Universal Tensor Compression — Deep2

## Runtime contract

The Deep2 GGUF loader preserves the original GGUF wire type and tensor metadata. F32 tensors use `WeightTensor::EnableCompressedF32` and reader-backed chunk storage. Already-quantized tensors can use `WeightTensor::EnableCompressedBytes`, which stores each byte range as an LZ4 block only when it shrinks and otherwise retains raw bytes. Each chunk independently selects:

- IEEE F16 when it satisfies the configured maximum absolute error.
- BF16 when it satisfies the configured maximum absolute error and is better than F16.
- Exact F32 when neither 16-bit representation satisfies the bound.

The compressed backing supports range reads and reader-backed construction. `BuildFromReader` reads one chunk at a time, so conversion scratch is bounded by the selected chunk size rather than the full tensor. CPU embedding and GEMV paths consume requested ranges/chunks rather than requiring a second full F32 matrix. The builder also enforces a maximum retained-byte budget before appending each chunk.

Uniform F16/BF16 chunk sets expose a stable zero-copy contiguous 16-bit view. The resident Vulkan path dispatches that payload through the packed QGEMV path and accumulates in F32. Mixed-encoding tensors and chunks requiring exact F32 do not qualify for this uniform GPU view. The host-bound Vulkan GEMV path decodes only bounded row tiles, repacks eligible tiles, and dispatches them into their final output-row windows; CPU GEMV uses the same bounded range-decode contract.

## Configuration

Compression is enabled by default on model load, subject to a shared 512 MiB retained-payload budget. F32 conversion defaults to zero absolute error, so only exactly representable 16-bit chunks are retained. Quantized-byte compression is lossless. Set these process environment variables before model loading to control the behavior:

```powershell
# Disable F32 conversion (default: enabled)
$env:RAWRXD_COMPRESS_F32 = "0"

# Permit bounded lossy F32 conversion (default tolerance: 0)
$env:RAWRXD_COMPRESS_F32_MAX_ABS_ERROR = "0.0001"

# Set the shared compressed-payload budget in MiB (default: 512)
$env:RAWRXD_COMPRESS_F32_BUDGET_MB = "1024"

# Disable lossless compression of quantized GGUF bytes (default: enabled)
$env:RAWRXD_COMPRESS_QUANTIZED_BYTES = "0"
```

The F32 tolerance is an absolute error bound, not a relative error or a quality preset. An invalid, negative, NaN, or infinite value disables F32 compression. The lower-level reader API also supports explicit relative-error mode, but Deep2 currently selects absolute-error mode. At the default zero tolerance, no lossy change is made.

The F32 chunk size used by Deep2 is currently the tensor input width (`cols`) so CPU GEMV can decode one output row at a time. Quantized byte tensors are compressed in 64 KiB LZ4/raw chunks. CPU and GPU paths reconstruct bounded row tiles (up to 256 KiB) and retain the existing GGML dequantization/kernel interpretation.

## Memory accounting

Do not equate compressed bytes with total process residency:

1. `storedBytes()` measures packed payload bytes only. `residentBytes()` additionally counts retained vector capacity and chunk metadata, and is the value used for cache admission and the model compression budget.
2. `GpuCompressedF32Payload` retains a shared owner and a zero-copy view into the canonical contiguous 16-bit backing; it does not allocate a second host copy.
3. Vulkan resident-weight bytes are accounted by the Vulkan weight window / compressed dispatch counters.
4. The original GGUF mapping remains alive and is still the backing source for other tensors. The current implementation does not unmap individual F32 tensor ranges or prove that their file-backed pages have left the process working set.

A valid runtime-memory claim must report packed payload bytes, retained host allocation bytes (`residentBytes()`), Vulkan device bytes, GGUF mapped bytes, and process working-set/RSS separately. Never report only the compressed tensor size as total memory saved.

## Cache and lifetime

`TensorResidencyCache` is instantiated for the model's configured F32 compression budget. Each successfully compressed F32 tensor is inserted under a stable shard/file-offset/name key and receives a `Lease` stored on its `WeightTensor`. The lease pins the immutable payload for the tensor's lifetime; cache admission is therefore an enforced model-load budget, while eviction is available only after tensor owners release their leases. The GPU payload retains the same canonical backing through its own shared owner. This avoids a duplicate compressed host allocation and makes ownership explicit. Active-model tensors are intentionally pinned; this is not a demand-paged LRU that evicts weights still referenced by the model.

## Supported and unsupported representations

- F32 is the precision-reduction input type: F16/BF16 is selected only when the configured error bound is met; otherwise each raw F32 chunk is tried with lossless LZ4 and retained in that encoding only when it is smaller than the original bytes.
- Existing GGML quantized tensors (Q2_K through Q8_K and other supported formats) keep their original GGML type and packed bytes. Optional lossless LZ4 chunk storage is used only when it reduces bytes; CPU/GPU paths restore bounded tiles before invoking the existing dequantization/GPU kernels. No lossy requantization is applied.
- F16/BF16 tensors are already 16-bit and are not converted by this path.
- F64 and integer tensors are not converted by this path.
- F32 LZ4 chunks are decompressed on the host only for the requested row/range before GPU upload; device-side LZ4/RLE decoding and per-tensor GGUF unmapping are not yet implemented. Compressed quantized and mixed-codec F32 row-tile GEMVs can now append to an already-active fused Vulkan command buffer through `DispatchGemvQuantRows`; other specialized fused/state/attention paths that still require direct mapped pointers remain migration work.

## Regression target

The native test target `rawrxd-native-tensor-compression-test` currently contains 69 explicit checks covering exact 16-bit compaction, zero-copy packed views, reader-bounded construction, absolute/relative error selection, NaN/infinity preservation, exact F32 fallback, mixed chunk encodings, LZ4 round trips, raw-byte fallback, range boundaries, storage budgets, and lease-aware cache admission/eviction. The model-load cache insertion/lease wiring is integrated but still requires a full Deep2 build and model-load runtime validation. A Windows CI workflow is configured to compile and run this standalone test with MSVC; no successful workflow receipt has yet been recorded. Full model numerical parity, end-to-end Vulkan inference, and process working-set measurements remain separate release gates.

## Compressed-only inference entry points

`WeightTensor::hasBacking()` treats raw mappings, chunked F32 backing, and losslessly compressed quantized-byte backing as valid tensor ownership. CPU `LinearW`, embeddings, RMSNorm, attention/FFN dispatch, MoE expert paths, and logits validation accept compressed-only tensors.

The production host-bound Vulkan GEMV path now prefers compressed backing even when the original GGUF mapping is still present. Its compressed quantized and mixed-F32 tile branches are eligible both for standalone dispatch and for an already-active fused command buffer:

- F32 row chunks with matching source encodings are coalesced into bounded GPU tiles. Existing F16/BF16 payload bytes are copied without re-quantization, preserving the original error bound; F32/LZ4 rows are expanded exactly. Each dispatch writes directly to its final output-row window.
- Losslessly compressed quantized-byte tensors are expanded only for bounded row tiles on the host, then uploaded in their original GGML packed block representation. The existing Vulkan shader performs native packed decoding for F16, BF16, Q8_0, Q2_K, Q4_K, and Q6_K. Unsupported quant types fail the GPU attempt and retain the existing CPU dequantization fallback when strict mode is disabled.
- Tile cache keys include tensor/backing identity, file/shard identity, row range, and type. The Vulkan cache validates a payload fingerprint and byte geometry before reusing a tile, failing closed on collisions.

When two Vulkan devices are available, compressed GEMV partitions output rows between them. Each device independently reads and expands only its own bounded source tiles, dispatches into a local output window, and downloads directly into a disjoint range of the final output vector. Both partitions must succeed before the route is reported as dual-GPU; otherwise the attempt is discarded and the existing single-device path is tried. This avoids a second full-size output merge buffer.

Each device transaction now holds its recursive Vulkan API lease across scratch allocation, upload, row-tile dispatches, and download. This prevents another agent from interleaving a request into shared per-device scratch buffers. Existing raw dual-GPU row-split, grouped, and batch helpers use the same device-lease discipline.

This is bounded host-side decompression followed by GPU-native arithmetic; it is not device-side LZ4 decompression. It avoids whole-tensor F32/quantized expansion, but the original GGUF mapping remains alive. Some fused/state/attention paths still consume direct mapped pointers, and source mapping reclamation remains gated on migrating every consumer and introducing per-tensor mapping ownership.

## Strict GPU execution contract

When `vulkanStrictNoCpuFallback_` is enabled, Deep2 rejects unsupported compressed-only weight execution instead of silently falling back to CPU range decoding. The host-bound GEMV path can consume compressed F32 and supported compressed quantized tiles in both standalone and active fused command recording. Other specialized fused/state/attention routes that still require raw mapped pointers remain gated until their owner-backed compressed-tile routes are migrated and independently validated. This does not yet establish full-model compressed-only GPU parity or GGUF mapping reclamation.
