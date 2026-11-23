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

Both model-binding routes now have opt-in admission via `RAWRXD_COMPRESSED_WEIGHT_RESIDENCY=1` before model load:
- The single-shard/single-file GGUF binder admits eligible named matrix projections and embedding matrices from the mapped tensor view.
- The standard multi-shard binder admits eligible two-dimensional matrix weights from the shard mapping cache and releases the mapping pin only after the compressed store accepts the tensor.
- Both preserve the original GGML type and packed bytes by default. The separate `RAWRXD_COMPRESSED_WEIGHT_F32_TO_F16=1` option is explicitly lossy and changes the resident GGML type to F16.
- Both enforce a per-model encoded-payload budget, defaulting to 4 GiB and configurable with `RAWRXD_COMPRESSED_WEIGHT_BUDGET_MB`. A tensor is admitted only when its encoded representation is smaller; otherwise it stays mapped.

Norms, vectors, biases, and any consumers that still require direct pointers remain mapped. The CPU LinearW range path reads only required rows. The opt-in Vulkan GEMV tile path stages bounded row-aligned slices; other Vulkan operators and direct-pointer consumers are not yet universally migrated. This is not yet universal all-tensor coverage.

The standalone test covers multi-block range reads, exact round trips for compressible and high-entropy data, duplicate-name rejection, bounds checks, and lease survival when the cache budget is reduced.


## Tensor precision policy

`addTensor(name, bytes, size, error, ggml_type)` stores an arbitrary GGML payload byte-for-byte and retains its GGML type ID. Use this for native quantized formats (Q4/Q5/Q6/Q8/IQ/etc.); no dequantization or re-quantization occurs.

`addTensorF32AsF16` is an explicit, opt-in lossy precision conversion. It converts IEEE-754 binary32 to binary16 using round-to-nearest, ties-to-even, then stores the result as GGML_TYPE_F16. It is not applied automatically to quantized inputs. Callers must validate model quality and kernel compatibility before selecting this representation.


## Automatic multi-shard model admission

Set `RAWRXD_COMPRESSED_WEIGHT_RESIDENCY=1` before loading a standard multi-shard model to enable compressed matrix admission. The current implementation:
- Reads the existing mapped tensor bytes directly into independently decodable 64 KiB blocks.
- Preserves the GGML type ID and packed quantized payload byte-for-byte.
- Rejects any tensor whose compressed payload is not strictly smaller than the source.
- Enforces a 512 MiB compressed payload budget per engine model.
- Releases the tensor-residency mapping pin only after successful compressed-store admission.
- Leaves norm/vector tensors mapped because their consumers have not all been migrated to range reads.

The default is OFF until full product validation completes. It currently applies to the standard multi-shard binder only, not the single-file GGUF path or every tensor consumer. The Vulkan GEMV adapter still requires one contiguous tensor pointer and therefore stages a full tensor for GPU dispatch. This is an implementation milestone, not a claim of universal compressed residency.

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
