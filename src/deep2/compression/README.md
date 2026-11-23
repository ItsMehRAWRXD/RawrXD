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

This is the first runtime-residency primitive plus an initial Deep2 kernel-consumer hook. `Deep2::WeightTensor` can attach a shared store/key and read byte ranges from either raw or compressed backing. `Deep2Engine::LinearW_Range` now reads only the packed rows assigned to each CPU worker, preserving the original GGML row layout. Single-range calls read only the rows required by that invocation. The existing Vulkan upload API still requires a contiguous base pointer, so the Vulkan branch stages the complete tensor for now. This enables the LinearW CPU/Vulkan call chain to consume compressed-only tensors. The standard multi-shard Deep2 binder now has an opt-in integration: set `RAWRXD_COMPRESSED_WEIGHT_RESIDENCY=1` before model load. Eligible matrix tensors are compressed from the existing mapped shard view, and the mapping-cache pin is released only after the compressed store accepts the tensor. Only tensors whose encoded representation is strictly smaller are admitted, under a 512 MiB per-model compressed-payload budget; otherwise the original mapped representation remains active. Norms and vectors remain mapped because their current consumers use direct pointers. Single-file GGUF loading and other direct-pointer consumers are not yet migrated, so this is not yet universal model coverage. The Vulkan upload API still stages a complete tensor. Future GPU block staging must preserve the existing submission-completion ownership protocol.

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
