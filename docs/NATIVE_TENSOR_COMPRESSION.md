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
- `TensorResidencyCache` retains only encodings that actually reduce bytes,
  enforces a configurable memory budget, tracks hits/misses/decoded bytes and
  evicts least-recently-used entries.
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
- F16/BF16 conversion remains opt-in through
  `compressedF32MaxAbsError`; its default is zero, so lossy conversion is
  never silently enabled. Exact F16/BF16 representations and lossless RLE
  may still be retained when they reduce storage.

This is an in-memory runtime cache, not a change to GGUF wire types. Existing
quantized weights remain encoded in the TensorROM pager; only the requested
blocks are expanded into the row tile consumed by the CPU or Vulkan GEMV.
Unsupported GGUF types (including IQ formats not yet implemented in this
decoder) fail closed rather than being interpreted with guessed geometry.

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
