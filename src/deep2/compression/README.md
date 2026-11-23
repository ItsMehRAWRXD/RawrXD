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

This is the first runtime-residency primitive plus an initial Deep2 kernel-consumer hook. `Deep2::WeightTensor` can attach a shared store/key and read byte ranges from either raw or compressed backing. `Deep2Engine::LinearW_Range` now reads only the packed rows assigned to each CPU worker, preserving the original GGML row layout. Single-range calls read only the rows required by that invocation. The existing Vulkan upload API still requires a contiguous base pointer, so the Vulkan branch stages the complete tensor for now. This enables the LinearW CPU/Vulkan call chain to consume compressed-only tensors, but the production GGUF loader does not yet populate/attach the store and other direct-pointer consumers remain unchanged. Full-model residency reduction is therefore NOT yet achieved. Future loader integration must preserve native quantized layouts and must not dequantize the full model to F32. GPU-side staging/reclamation must additionally use the existing submission-completion ownership protocol before reusing or releasing device resources.

The standalone test covers multi-block range reads, exact round trips for compressible and high-entropy data, duplicate-name rejection, bounds checks, and lease survival when the cache budget is reduced.


## Tensor precision policy

`addTensor(name, bytes, size, error, ggml_type)` stores an arbitrary GGML payload byte-for-byte and retains its GGML type ID. Use this for native quantized formats (Q4/Q5/Q6/Q8/IQ/etc.); no dequantization or re-quantization occurs.

`addTensorF32AsF16` is an explicit, opt-in lossy precision conversion. It converts IEEE-754 binary32 to binary16 using round-to-nearest, ties-to-even, then stores the result as GGML_TYPE_F16. It is not applied automatically to quantized inputs. Callers must validate model quality and kernel compatibility before selecting this representation.
