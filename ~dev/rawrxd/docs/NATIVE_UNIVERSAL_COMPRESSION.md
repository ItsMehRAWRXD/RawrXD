# Native Universal Tensor Compression — Deep2

## Runtime contract

The Deep2 GGUF loader preserves the original GGUF wire type and tensor metadata. For F32 tensors, `WeightTensor::EnableCompressedF32` builds an immutable, chunked backing store. Each chunk independently selects:

- IEEE F16 when it satisfies the configured maximum absolute error.
- BF16 when it satisfies the configured maximum absolute error and is better than F16.
- Exact F32 when neither 16-bit representation satisfies the bound.

The compressed backing supports range reads and reader-backed construction. `BuildFromReader` reads one chunk at a time, so conversion scratch is bounded by the selected chunk size rather than the full tensor. CPU embedding and GEMV paths consume requested ranges/chunks rather than requiring a second full F32 matrix. The builder also enforces a maximum retained-byte budget before appending each chunk.

Uniform F16/BF16 chunk sets expose a stable zero-copy contiguous 16-bit view. The resident Vulkan path dispatches that payload through the packed QGEMV path and accumulates in F32. Mixed-encoding tensors and chunks requiring exact F32 do not qualify for this uniform GPU view and use the CPU range-decode path.

## Configuration

Set the following process environment variable before model loading:

```powershell
$env:RAWRXD_COMPRESS_F32_MAX_ABS_ERROR = "0.0001"
```

The value is an absolute error bound, not a relative error or a quality preset. Use model-specific parity measurements to choose it. An invalid, negative, NaN, or infinite value is ignored. Compression is opt-in when the variable is absent; this avoids silently changing model numerics.

The chunk size used by Deep2 is currently the tensor input width (`cols`) so CPU GEMV can decode one output row at a time.

## Memory accounting

Do not equate compressed bytes with total process residency:

1. `ChunkedF32Storage::storedBytes()` measures the private compressed payload.
2. `GpuCompressedF32Payload` retains a shared owner and a zero-copy view into the canonical contiguous 16-bit backing; it does not allocate a second host copy.
3. Vulkan resident-weight bytes are accounted by the Vulkan weight window / compressed dispatch counters.
4. The original GGUF mapping remains alive and is still the backing source for other tensors. The current implementation does not unmap individual F32 tensor ranges or prove that their file-backed pages have left the process working set.

A valid runtime-memory claim must report private compressed bytes, GPU payload bytes, Vulkan device bytes, GGUF mapped bytes, and process working-set/RSS separately. Never report only the compressed tensor size as total memory saved.

## Cache and lifetime

`TensorResidencyCache` is a bounded, thread-safe LRU for immutable `ChunkedF32Storage` payloads. A `Lease` holds shared ownership; eviction and erase refuse to reclaim a payload while a lease is active. The cache implementation is currently a reusable primitive and is not yet wired into Deep2 per-weight ownership/eviction. The per-weight `shared_ptr` and GPU payload lifetime remain authoritative.

## Supported and unsupported representations

- F32 is the current lossy precision-reduction input type.
- Existing GGML quantized tensors (Q2_K through Q8_K and other supported formats) already remain in their native packed representations and use their existing dequantization/GPU kernels. They are not automatically requantized by this F32 path.
- F16/BF16 tensors are already 16-bit and are not converted by this path.
- F64 and integer tensors are not converted by this path.
- Mixed per-chunk GPU descriptors, device-side streaming decompression for nonuniform chunks, and per-tensor GGUF unmapping are not yet implemented.

## Regression target

The native test target `rawrxd-native-tensor-compression-test` covers exact 16-bit compaction, selective range decode, exact F32 fallback, mixed chunk encodings, and lease-aware cache eviction. The Windows CI workflow compiles and runs this standalone test with MSVC. Full model numerical parity, end-to-end Vulkan inference, and process working-set measurements remain separate release gates.
