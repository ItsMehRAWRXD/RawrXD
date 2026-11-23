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

This is the first runtime-residency primitive, not a claim of completed inference integration. The current branch does not yet route GGUFLoader, Deep2 WeightTensor, CPU GEMV, or Vulkan staging through this store. That wiring must preserve existing quantized kernels and tensor layouts; it must not dequantize the full model to F32. GPU-side staging/reclamation must additionally use the existing submission-completion ownership protocol before reusing or releasing device resources.

The standalone test covers multi-block range reads, exact round trips for compressible and high-entropy data, duplicate-name rejection, bounds checks, and lease survival when the cache budget is reduced.
