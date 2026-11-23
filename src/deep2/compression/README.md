# Native compressed weight residency (initial implementation)

This directory contains a dependency-free C++20 block store for keeping arbitrary tensor bytes compressed in host memory and decoding only the independently addressable blocks requested by a consumer.

## Contract

- The stored representation is byte-exact. It does not alter GGUF tensor type, quantization metadata, dimensions, strides, or numerical values.
- Tensor payloads are split into independently decodable blocks (64 KiB by default).
- Each block uses a small LZ-style back-reference codec. If encoding is not smaller, the block is retained raw; incompressible tensors therefore do not expand.
- Each decoded block is CRC-32 checked before it is exposed.
- `acquireBlock` returns a shared lease. A live lease pins its decoded bytes and cannot be invalidated by cache eviction.
- The decoded cache has a configurable byte budget and LRU eviction. If every cached block is pinned by active readers, the cache temporarily remains above budget rather than invalidating a lease.
- `readRange` acquires only the blocks intersecting the requested byte range.

## Build and test

This component currently has an isolated native CMake project:

```powershell
cmake -S src/deep2/compression -B build/compressed-weight-store
cmake --build build/compressed-weight-store --config Release
ctest --test-dir build/compressed-weight-store -C Release --output-on-failure
```

## Integration status

This is the runtime-residency primitive plus Deep2 kernel-consumer integration. `Deep2::WeightTensor` can attach a shared store/key and read byte ranges from either raw or compressed backing. `Deep2Engine::LinearW_Range` reads only the packed rows assigned to each CPU worker, preserving the original GGML row layout. Single-range calls read only the rows required by that invocation.

Both model-binding routes have opt-in admission via `RAWRXD_COMPRESSED_WEIGHT_RESIDENCY=1` before model load:
- The single-shard/single-file GGUF binder admits eligible named matrix projections, embedding matrices, and one-dimensional F32/F16 normalization vectors.
- The standard multi-shard binder admits eligible two-dimensional matrix weights and one-dimensional F32/F16 normalization vectors from the shard mapping cache, releasing the mapping pin only after the compressed store accepts the tensor.
- Both preserve the original GGML type and packed bytes by default. The separate `RAWRXD_COMPRESSED_WEIGHT_F32_TO_F16=1` option is explicitly lossy and changes the resident GGML type to F16.
- Both enforce a per-model encoded-payload budget, defaulting to 4 GiB and configurable with `RAWRXD_COMPRESSED_WEIGHT_BUDGET_MB`. A tensor is admitted only when its encoded representation is smaller; otherwise it stays mapped.

The CPU LinearW range path reads only required matrix rows. Token embedding lookup reads only the selected packed row. RMSNormW now reads only the required F32/F16 norm prefix into a request-local vector and no longer requires a mapped pointer. Q/K/V projection biases now use bounded range reads; other biases and vectors remain mapped until their direct-pointer consumers are migrated. The opt-in Vulkan GEMV tile path stages bounded row-aligned slices; other Vulkan operators and direct-pointer consumers are not yet universally migrated. This is not yet universal all-tensor coverage.

The standalone test covers multi-block range reads, exact round trips for compressible and high-entropy data, duplicate-name rejection, bounds checks, and lease survival when the cache budget is reduced.


## Tensor precision policy

`addTensor(name, bytes, size, error, ggml_type)` stores an arbitrary GGML payload byte-for-byte and retains its GGML type ID. Use this for native quantized formats (Q4/Q5/Q6/Q8/IQ/etc.); no dequantization or re-quantization occurs.

`addTensorF32AsF16` is an explicit, opt-in lossy precision conversion. It converts IEEE-754 binary32 to binary16 using round-to-nearest, ties-to-even, then stores the result as GGML_TYPE_F16. It is not applied automatically to quantized inputs. Callers must validate model quality and kernel compatibility before selecting this representation.


## Automatic multi-shard model admission

Set `RAWRXD_COMPRESSED_WEIGHT_RESIDENCY=1` before loading a model to enable opt-in admission in both the single-shard GGUF binder and the standard multi-shard binder. The current implementation:
- Streams mapped tensor bytes directly into independently decodable 64 KiB blocks.
- Preserves the GGML type ID and packed payload byte-for-byte by default.
- Admits eligible matrix projections, token embedding matrices, and one-dimensional F32/F16 norm vectors when the encoded payload is strictly smaller.
- Enforces the configurable per-model compressed payload budget (4 GiB default).
- Releases the multi-shard tensor mapping pin only after successful compressed-store admission.
- Keeps biases, non-F32/F16 norm formats, and unsupported direct-pointer consumers mapped.
- Reads token embedding rows and RMSNorm vector prefixes from compressed backing without retaining decoded tensors.

The default is OFF until full product validation completes. The Vulkan GEMV adapter supports opt-in bounded row-tile staging, but other Vulkan operators and direct-pointer consumers are not yet universally migrated. This is an implementation milestone, not a claim of universal compressed residency.

## Q4_0 compressed-resident CPU kernel

The bounded resident matvec now supports GGML Q4_0 in addition to F32, F16,
and Q8_0. Q4_0 rows are consumed as native 18-byte blocks (binary16 scale plus
16 packed nibble bytes); the kernel maps low nibbles to columns 0-15 and high
nibbles to columns 16-31, then applies the GGML signed offset of -8. The
compressed store retains the original Q4_0 payload and GGML type ID. No
dequantized full matrix is allocated.

A dedicated CTest fixture checks both nibble lanes, nonuniform activations,
byte-exact packed roundtrip, wrong-type rejection, and invalid column geometry.
This is a CPU operator implementation only; it does not imply that every
Q4_0 Deep2 dispatch path or Vulkan shader has been redirected to this reader.

## Bounded Vulkan row-tile staging

The Deep2 LinearW GPU path now has an opt-in compressed-weight tile mode:

- RAWRXD_COMPRESSED_WEIGHT_GPU_TILED=1 enables row-aligned staging from
  compressed backing into the existing Vulkan GEMV ABI.
- RAWRXD_COMPRESSED_WEIGHT_GPU_TILE_BYTES sets the maximum host staging
  allocation per tile (default 16 MiB). A single packed row may exceed the
  configured budget because a row cannot be split across the current GEMV ABI.
- The same reusable host buffer is used for every tile. Vulkan GEMV dispatch
  waits for submission completion before returning, so the staging buffer is
  not reused while its upload is in flight.
- Each tile carries a distinct source-offset-derived cache key, preventing
  same-name/same-shape row slices from aliasing in the GPU weight cache.
- If a tile read or dispatch fails, the GPU attempt is abandoned; the existing
  CPU compressed-row path remains the fallback unless strict GPU mode forbids it.
- RAWRXD_COMPRESSED_WEIGHT_GPU_STAGING=1 remains the separate full-tensor
  staging override and takes precedence over tiled staging.

The tile planner has a standalone CTest for row coverage, offsets, budget
limits, oversized single rows, invalid geometry, and overflow. This is a
bounded staging implementation for the existing GEMV path; it is not yet a
claim that all Vulkan operators or every tensor consumer use block-resident
weights.

## Q4_1, Q5_0 and Q5_1 compressed-resident CPU kernels

The bounded CPU matvec reader now also understands the GGML block layouts for
Q4_1 (20 bytes per 32 values), Q5_0 (22 bytes), and Q5_1 (24 bytes):

- Q4_1 reads binary16 scale and minimum followed by 16 packed nibble bytes.
- Q5_0 reads binary16 scale, four high-bit bytes, and 16 packed nibble bytes;
  it reconstructs signed 5-bit values with the GGML -16 offset.
- Q5_1 reads binary16 scale and minimum, four high-bit bytes, and 16 packed
  nibble bytes; it reconstructs affine unsigned 5-bit values.
- The stored GGML type IDs (3, 6 and 7) are checked before dispatch.
- The packed source bytes remain unchanged in compressed residency.

A dedicated CTest exercises the two nibble lanes, Q5 high-bit extraction,
scale/minimum application, and exact stored-byte roundtrips. This extends the
standalone CPU resident matvec adapter; it does not yet route every production
Deep2 operator or Vulkan shader for these types through the compressed reader.

## Production Deep2 row-slice format geometry

The Deep2 LinearW range reader's packed-row geometry currently covers F32,
F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K and
NVFP4. The compressed store itself is format-agnostic and retains other GGML
payloads byte-for-byte, but a tensor is admitted to this LinearW path only when
its row format has a known packed stride and the logical row width is aligned
to that format's block size. Invalid/non-aligned geometry now rejects
compressed admission rather than rounding up and risking a kernel over-read.

## Compressed-resident row dequantization and synthetic model E2E

`StoredTensorReadRow` now performs one-row embedding-style lookup directly
from compressed backing for F32, F16, Q4_0, Q4_1, Q5_0, Q5_1 and Q8_0. It
validates the stored GGML type, matrix row geometry and bounds, reads only the
selected packed row, and dequantizes that row into the caller's activation
buffer. The Q4/Q5 fixtures check decoded row sums as well as matvec parity.

The synthetic GGUF v3 acceptance fixture now contains an embedding matrix, a
Q4_0 attention projection and an output/logit matrix. It exercises actual
mapped GGUF parsing, whole-model compressed admission, closes the source mmap,
performs a selected-token embedding lookup, runs the resident projection and
output head, compares both operations with the direct uncompressed reader,
selects the next token by greedy argmax, and rejects a truncated model. This is
a deterministic miniature loader-to-logits-to-token-selection path; it is not
a claim of full production transformer architecture coverage or language
quality.

## RMSNorm vector residency

Both single-shard and standard multi-shard binders now admit one-dimensional
F32/F16 tensors whose names identify normalization weights, provided the
lossless block encoding is strictly smaller and the per-model budget allows
admission. The original GGML type and bytes are preserved unless the separately
opted-in F32-to-F16 conversion is selected.

`Deep2Engine::RMSNormW` accepts either raw or compressed backing. For compressed
F32/F16 norms it reads only the requested vector prefix into a request-local
buffer, then uses the same AVX2/scalar normalization path. It validates type,
length, and read errors before consuming the vector. No decoded norm tensor is
retained in the store cache by this consumer. Biases and non-F32/F16 vector
consumers remain mapped until their direct-pointer paths are migrated.

The isolated smoke suite includes F32/F16 norm-vector block admission, exact
prefix and nonzero-range reads, and zero decoded-cache retention. Full Deep2
RMSNorm model parity still requires the native integration build and reference
inference validation.

## Deep2 normalization and Mamba-2 consumer coverage

Compressed backing is now recognized by the inference call sites as a valid
weight source. The final normalization gate in both prompt processing and
autoregressive decode, the output/logit head gate, the dedicated mixer-norm
selection, and Gemma sandwich norm gates use the unified raw-or-compressed
WeightTensor backing predicate. This prevents the null raw pointer that is
intentional for compressed residency from skipping required inference stages.

RMSNorm admission is restricted to the F32/F16 vector names actually consumed
by RMSNormW, including per-head Q/K normalization vectors. Per-head Q/K norms are represented as compressed byte-offset views and read
one head at a time through RMSNormW. SSM channel norms use the dedicated
Mamba-2 vector materializer rather than the RMSNorm consumer.

The single-shard GGUF binder additionally admits eligible attention-bias
vectors and Mamba-2 tensors:
- F32/F16 attention Q/K/V bias vectors are read through a request-local
  projection-bias resolver; the Q/K/V LinearW calls retain the existing ABI.
- ssm_in and ssm_out matrices use the existing LinearW compressed row-range
  path.
- ssm_conv1d matrices and the ssm_a, ssm_d, ssm_dt_bias,
  ssm_conv1d_bias, and ssm_norm vectors are admitted only as F32 where their
  consumers are explicitly range-aware.
- computeSSM reads compressed custom-consumer tensors into request-local
  buffers and supports F32 as well as the separately opted-in F16 conversion.
  It validates element counts against the dimensions used by the selective
  scan before reading values.
- Unsupported legacy SSM tensors remain mapped. Multi-shard SSM binding is
  not claimed by this change.

The Mamba-2 convolution kernel is fully consumed each token, so its current
custom consumer reads that complete kernel into a temporary buffer; LinearW
matrices continue to read only worker row ranges. The store's decoded-block
cache can reuse verified blocks within its configured budget.

This expands consumer coverage but does not establish complete Deep2 model
parity. The native engine build, Mamba-2 reference comparisons, long-context
decode, and Vulkan parity still require execution on the target build matrix.
Per-head Q/K normalization vectors are also admitted when their tensor names
match the Q/K norm bindings. Attention Q/K/V bias vectors are admitted only
for the three projection consumers that now materialize compressed ranges.
WeightTensor subviews carry a checked byte offset
into the compressed source tensor, allowing each head's F32/F16 prefix to be
read independently. The Q-norm diagnostic path uses an explicit range read
when the source is compressed and avoids assuming a second head exists in a
single-head vector.

