# Native GGUF tensor compression

## Build

The standalone compressor has no external codec dependency:

```sh
c++ -std=c++17 -O2 tools/native_gguf_f16.cpp -o native_gguf_f16
```

The production `~dev/rawrxd` CMake project exposes the same executable as
`rawrxd-native-gguf-compress` (option `RAWRXD_BUILD_NATIVE_GGUF_COMPRESSOR`,
enabled by default).

## Use

```sh
native_gguf_f16 input.gguf output.gguf 0.02 auto
native_gguf_f16 input.gguf output-q2.gguf 0.10 q2_k
native_gguf_f16 input.gguf output-q3.gguf 0.05 q3_k
native_gguf_f16 input.gguf output-q4.gguf 0.02 q4_k
native_gguf_f16 input.gguf output-q5.gguf 0.01 q5_k
native_gguf_f16 input.gguf output-q6.gguf 0.001 q6_k
```

The tolerance is a maximum absolute reconstruction error in the source
tensor's value units. A format is accepted only when every block in the
whole tensor passes. `auto` tries Q2_K, Q3_K, Q4_K, Q5_K, then Q6_K in
increasing storage order; if no K format passes, the existing native
quantization/FP16 fallback selection continues. Manual format selection is
fail-closed: rejected tensors retain their original type and bytes.

Supported floating source types are F64, F32, F16, and BF16. The writer
preserves tensor names, dimensions, metadata, alignment, and untouched
tensor payloads. It writes standard GGUF type IDs and canonical block sizes:
Q2_K 84 B, Q3_K 110 B, Q4_K 144 B, Q5_K 176 B, Q6_K 210 B, and Q8_K 292 B per 256 values. Q8_K is available as an explicit mode; automatic selection compares the smaller K formats and Q8_0 first.

## Deep2 and model loading

The production Deep2 `GGUFLoader` recognizes type IDs 10–14 and validates
their block geometry. `QuantKernelRegistry` has registered dequantization
and scalar GEMV paths for Q2_K through Q6_K; Q4_K also has its existing
specialized path. The integration test creates real GGUF files and loads
each K type through the mapped Deep2 loader.

## Runtime compression controls

The ROM engine sizes its two compressed-residency budgets from available
physical memory, with conservative defaults and hard caps. Operators can
override those budgets in MiB before launch:

- `DEEP2_F32_RESIDENCY_MB`: compressed F32 chunk budget (default is derived
  from available RAM; capped at 2 GiB).
- `DEEP2_ENCODED_RESIDENCY_MB`: lossless encoded-byte budget (default is
  derived from available RAM; capped at 512 MiB).
- `DEEP2_F32_MAX_ABS_ERROR`: optional finite, nonnegative absolute error
  allowance for per-chunk F32-to-F16/BF16 storage. Unset or zero preserves
  values exactly; lossy storage is never silently enabled.

Native callers can instead use
`Deep2Engine::ConfigureTensorCompression(f32Bytes, encodedBytes, maxAbsError)`.
It validates the error allowance, updates both synchronized cache budgets,
and publishes the precision policy atomically for concurrent inference.
A zero byte budget disables admission to that cache; reads continue through
the bounded TensorROM pager path.

## Canonical GGUF geometry

The ROM path uses canonical GGML type IDs and block byte counts rather than
shifted K-type labels or guessed block sizes:

| GGUF type | Values per block | Bytes per block |
|---|---:|---:|
| Q4_0 / Q4_1 / Q5_0 / Q5_1 | 32 | 18 / 20 / 22 / 24 |
| Q8_0 / Q8_1 | 32 | 34 / 36 |
| Q2_K / Q3_K / Q4_K / Q5_K / Q6_K / Q8_K | 256 | 84 / 110 / 144 / 176 / 210 / 292 |

TensorROM validates rank, dimension-product overflow, row/block alignment,
known type IDs, payload bounds and exact partial-read ranges. It honors
`general.alignment` (32-byte GGUF default) rather than assuming 64 bytes.

## Compressed in-memory F32 residency

The file writer is not the runtime memory solution. Deep2 now has a separate
private resident representation in `src/deep2/NativeTensorCompression.hpp`
and `src/deep2/NativeTensorResidencyCache.hpp`:

- `ChunkedF32Storage::BuildFromReader` builds the representation by reading
  bounded source chunks from a callback. It never stages the complete F32
  tensor in an intermediate buffer. The cache probes the first bounded chunk
  and rejects a non-compressible tensor immediately rather than scanning the
  entire model before falling back to raw tile reads.
- `TensorByteResidencyCache` independently stores losslessly RLE/LZ4-compressed
  chunks of already-encoded GGUF payloads when they are smaller. Deep2 uses it
  for F16/BF16, fixed-block quantized and K-quant tensor bytes. Once a complete
  compressed representation is admitted, the corresponding unleased raw
  TensorROM pages are evicted so the pager and compressed cache do not retain
  duplicate full payloads.
- `TensorResidencyCache` and `TensorByteResidencyCache` retain only
  encodings that actually reduce bytes, enforce configurable memory budgets,
  track hits/misses/decoded bytes and evict least-recently-used entries.
  In-flight range reads pin their entries: eviction skips pinned storage,
  budget reductions are completed when the final read releases its pin, and
  model-clear waits for active readers before releasing representations.
  A changed budget invalidates raw-only admission memoization so tensors can
  be reconsidered under the new capacity; setting the same budget preserves
  the memoized decision.
- Range reads decompress only the chunks intersecting the requested range
  into caller-owned output memory. A caller can reuse a scratch buffer; the
  cache does not retain an expanded F32 copy.
- `Deep2Engine::readCompressedF32Tile` streams F32 tensor chunks from the
  TensorROM pager into compressed resident storage. If no safe encoding saves
  space or the cache budget cannot admit the tensor, it reads only the
  requested raw tile instead of duplicating the tensor.
- `Deep2Engine::gemvTensorROM` computes GEMV in bounded row tiles.
  The Phi-3 ROM forward path uses it for token embeddings, QKV, FFN up/down
  and output projection. F32 tiles come from compressed resident chunks;
  F16/BF16/F64, integer, Q4/Q5/Q8 fixed-block and Q2_K–Q8_K tiles are read
  as encoded GGUF blocks and decoded only into the current tile scratch.
- `dequantizeTensorRange` validates block alignment and exact source byte
  counts before decoding. K-quant decoding delegates to the independent
  `NativeKQuant` GGML-layout codec; the old guessed 82/114/146/178-byte
  K-block layouts and incorrect shifted type IDs are no longer used by this
  ROM inference path.
- `gemvTensorROMVulkan` shares the same tile readers and submits one bounded
  F32 weight tile at a time; it publishes output only after all tile calls
  succeed.
- The native Deep2 Vulkan QGEMV path can retain uniform F16/BF16 compressed
  F32 weights in device-local storage. Its shader reads packed 16-bit values
  directly and accumulates in F32; mixed-codec chunks fail closed to the
  existing F32 path. This is opt-in through compressed-F32 preparation and
  its numerical-error budget; weights are never silently quantized.
- F16/BF16 conversion remains opt-in through
  `compressedF32MaxAbsError`; its default is zero, so lossy conversion is
  never silently enabled. Exact F16/BF16 representations and lossless RLE/LZ4
  may still be retained when they reduce storage.

Deep2 exposes `GetTensorResidencySnapshot()` with per-cache logical bytes,
compressed bytes, budgets, tensor counts, hit/miss counts, decoded bytes,
evictions, active compressed-range readers and the live TensorROM pager
resident-byte count. Active-reader counts make pinned storage visible during
concurrent inference and return to zero after each range operation. The snapshot also
reports total tracked weight residency (compressed caches plus resident pager
pages), so savings can be measured rather than inferred from file size.

Residency budgets adapt to available physical memory and can be overridden
with `DEEP2_F32_RESIDENCY_MB` and `DEEP2_ENCODED_RESIDENCY_MB`.
Lossy F32 conversion is opt-in through `DEEP2_F32_MAX_ABS_ERROR`; invalid,
negative or non-finite values are rejected. The default error budget is zero.

This is an in-memory runtime cache, not a change to GGUF wire types. Existing
quantized weights remain encoded in the TensorROM pager; only the requested
blocks are expanded into the row tile consumed by the CPU or Vulkan GEMV.
Unsupported GGUF types (including IQ formats not yet implemented in this
decoder) fail closed rather than being interpreted with guessed geometry.

### Direct packed-F32 Vulkan GEMV

The separate native Deep2 Vulkan QGEMV path supports packed F16 and BF16 weight
views. To opt in to compressing eligible F32 model weights before the GPU
residency pass, set:

- `DEEP2_F32_GPU_COMPRESSION=1`
- `DEEP2_F32_MAX_ABS_ERROR=0` (default; only exact F16/BF16 conversions qualify)
- `DEEP2_F32_GPU_COMPRESSED_BUDGET_MB=512` (bounded host-side packed payload)

A positive finite absolute-error tolerance explicitly permits lossy F16/BF16
conversion. The runtime considers only transformer matrix weights consumed by the
packed QGEMV path (dense attention/FFN, MLA, MoE and SSM projections). Norm
vectors, biases, embeddings and convolution/state vectors retain their
existing upload and residency accounting. A matrix is admitted only when its
complete chunk set uses one uniform 16-bit encoding and its packed payload
fits the configured budget. Mixed codecs, unsupported encodings, invalid
settings and failed admissions stay on the original F32 route. The Vulkan
QGEMV shader reads the packed bytes directly and performs F32 accumulation;
it does not allocate a full F32 weight matrix on the device.

## Verification gates

- The native block tests cover positive-only, negative-only, mixed-sign, and
  zero subgroups, plus strict-error rejection.
- The GGUF integration tests decode the written blocks independently and
  verify F64/F32/F16/BF16 source handling, automatic selection, and
  byte-for-byte fallback for non-finite or out-of-budget tensors.
- GitHub Actions compiles and runs the native tests on Linux and Windows.
  A queued workflow is not a passing result; record the completed run SHA
  and both platform conclusions before promotion.
- Model-level inference parity and VRAM/runtime benchmarks remain separate
  acceptance gates. File-size reduction alone is not evidence of inference
  parity.

## REAP boundary

This branch contains no REAP source/entrypoint to patch. The compressor emits
ordinary GGUF files with standard GGML type IDs, so a REAP workflow using the
Deep2 loader can consume the resulting file without a private container
format. A direct REAP invocation hook is not claimed until its owning source
is present and wired.
