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

The standalone synthetic GGUF test covers TensorROM, the shard pager, F32/encoded-byte caches, partial reads, and deterministic toy projection. The Windows `Deep2CompressedModelE2E` test additionally calls the existing Deep2 Phi-3 ROM forward method using a tiny generated model, a 4096x16 F16 output projection spanning two 64 KiB encoded chunks, and the CPU tiled GEMV path. This verifies F16 bytes enter the lossless encoded cache while the F32 layers use the F32 cache; each 16-row output tile requests only its encoded byte interval and the test checks encoded-cache hits, decode accounting, and every output logit against an independent analytic oracle for the synthetic attention/FFN/LayerNorm/output graph. The Vulkan packed-F16 path shares the same encoded-range helper but still requires target-GPU validation.

The current Phi-3 ROM forward method retains its existing simplified V-path attention behavior. Passing the synthetic test is evidence of compressed-residency plumbing through that method, not evidence of complete transformer architecture fidelity, production-model parity, Vulkan numerical parity, or release certification. Those gates require independent reference logits and target-hardware validation.


## Residency accounting boundary

The cache's retained-byte budget counts the reserved per-chunk directory
(`vector<Result>::capacity() * sizeof(Result)`) and each encoded payload's
actual `vector<uint8_t>::capacity()`, not merely the payload's logical size.
Admission checks the directory estimate before reserving it, then checks each
payload allocation before retaining the chunk. This prevents tiny chunk sizes
from creating an unbounded metadata allocation outside the configured cache
budget.

The reported compressed-byte total is the cache-owned chunk directory plus
payload allocation capacity. It is not process RSS or total host/device
residency: allocator bookkeeping, map nodes, caller-owned decode scratch,
temporary admission buffers, pager pages, Vulkan staging, and GPU allocations
are separate measurements and must be reported independently.

If a budget reduction occurs while readers hold leases, those pinned entries
remain alive until the readers finish. The cache may temporarily report an
over-budget state during that lease window, but it rejects new admissions
without unsigned-size underflow and retries them after leases drain. A
temporary capacity miss is not memoized as an intrinsically uncompressible
tensor. The same guarded admission rule is applied to both the F32
`TensorResidencyCache` and the byte-preserving
`TensorByteResidencyCache`. Once active leases have drained, the configured
budget is enforced against the cache's accounted retained storage; it is not
a cap on total process memory.

## Bounded packed GPU staging primitive

`ChunkedF32Storage::CopyUniform16BitRange(first, count, encoding, destination, destinationBytes)` copies only the requested F16/BF16 range into a caller-owned staging allocation. It validates the complete intersecting chunk span and destination capacity before writing. The destination remains unchanged on invalid ranges, mixed codecs, insufficient capacity, or missing storage. It supports windows crossing chunk boundaries without allocating or concatenating a whole-tensor packed buffer. The caller owns staging lifetime and must retain it through the GPU fence; this method alone does not dispatch a Vulkan kernel or prove GPU numerical parity.

## Release-mode test integrity

The three native codec and residency-cache test executables contain 225
assertion-based checks, including registration and range-read calls inside
assert expressions. Defining `NDEBUG` would otherwise remove both the checks
and those calls, allowing a false-green test. Each test translation unit now
undefines `NDEBUG` before including `<cassert>`; the standalone Linux and
MSVC CI compilation explicitly defines `NDEBUG` to exercise this Release
configuration. The synthetic GGUF and Deep2 model E2E executables use
explicit runtime checks instead. A green CI run after this change verifies
that the assertions were actually executed; it does not by itself establish
production-model or GPU parity.
