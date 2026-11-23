# Native compressed tensor residency

## Purpose

RawrXD does not need to rewrite GGUF files to reduce runtime weight residency. The paged ROM loader remains the source of truth; the Deep2 engine may admit a tensor into a bounded, private compressed representation after its first access. Subsequent inference reads decode only the chunks intersecting the requested element/byte range.

The on-disk GGUF format and canonical quantized tensor bytes are unchanged.

## Storage policy

| Source tensor | Resident representation | Correctness |
|---|---|---|
| F32 | Chunked adaptive RLE/LZ4; optional F16/BF16 only with explicit finite absolute-error budget | Lossless by default |
| F16/BF16 and quantized GGUF payloads | Lossless chunked byte codec | Bit-exact encoded bytes |
| Non-beneficial or over-budget tensor | Existing paged ROM source | No duplicate cache copy |

Admission is streamed from TensorROM. Candidate construction is bounded by the configured cache budget. A tensor is retained only when the complete private representation is smaller than its logical bytes. Deterministic no-win/budget rejections are memoized; transient source I/O and allocation failures remain retryable. On successful admission, unleased raw pager pages covering the tensor are evicted.

## Runtime controls

- `DEEP2_F32_RESIDENCY_MB`: F32 compressed-cache budget in MiB.
- `DEEP2_ENCODED_RESIDENCY_MB`: non-F32 encoded-byte cache budget in MiB.
- `DEEP2_F32_CACHE_BYTES`: byte-level override for the F32 cache.
- `DEEP2_ENCODED_CACHE_BYTES`: byte-level override for the encoded-byte cache.
- `DEEP2_F32_MAX_ABS_ERROR`: optional finite nonnegative absolute-error bound that permits F32-to-F16/BF16 chunks. Default is `0`, preserving exact F32 values.

All non-F32 encoded tensors use the same range-reader for cache admission and partial decode, including the packed F16/BF16 Vulkan GEMV path; this avoids bypassing compressed residency for already-compact source weights. The byte-level settings are applied during engine initialization. The explicit `ConfigureTensorCompression` API can override both budgets and the F32 tolerance after initialization. Set a tolerance only after comparing full-model logits and task quality against an independent reference.

## Observability

`Deep2Engine::GetTensorResidencySnapshot()` reports:
- F32 and encoded logical bytes versus compressed bytes.
- Configured cache budgets and retained tensor counts.
- Source pager budget, resident bytes, and page count.
- Cache hits/misses, decoded bytes, evictions, and active readers.

Do not interpret compressed-cache bytes alone as total process memory. Include source pager residency, decode scratch, output/activation buffers, allocator overhead, Vulkan staging/device allocations, and model metadata when measuring real peak RSS/VRAM.

## Verification

Configure and build with the repository's normal Windows CMake toolchain, then run:

```powershell
ctest --test-dir build -C Release -R "NativeTensor|NativeCompressedGGUF|Deep2CompressedModelE2E|ZlibAutoDetectSmoke|BrutalGzipRoundtrip" --output-on-failure
```

The standalone synthetic GGUF test covers TensorROM, the shard pager, F32/encoded-byte caches, partial reads, and deterministic toy projection. The Windows `Deep2CompressedModelE2E` test additionally calls the existing Deep2 Phi-3 ROM forward method using a tiny generated model, a 16x16 F16 output projection, and the CPU tiled GEMV path. This verifies F16 bytes enter the lossless encoded cache while the F32 layers use the F32 cache. The Vulkan packed-F16 path shares the same encoded-range helper but still requires target-GPU validation.

The current Phi-3 ROM forward method retains its existing simplified V-path attention behavior. Passing the synthetic test is evidence of compressed-residency plumbing through that method, not evidence of complete transformer architecture fidelity, production-model parity, Vulkan numerical parity, or release certification. Those gates require independent reference logits and target-hardware validation.
