# REAP / ROM / Pinball bridge — opt-in source

This is a **source integration seam**, not a certified end-to-end 671B runtime.
It introduces no external dependencies, does not modify original GGUF shards, and is not enabled in production.

## Verified repository interfaces
- `src/deep2/K2GlobalTensorIndex.hpp`: `FindExpertSlice`, `ShardPath`
- `src/deep2/K2ShardIo.hpp`: `K2ShardIo_Read(path, offset, dst, n)`
- `src/deep2/MoERouter.hpp`: `TokenRoute.topExperts`
- `src/deep2/Deep2LivePath.hpp`: layer start/end hooks
- `src/deep2/lavapath/SlingshotLaw.hpp`: residency policy, not a 1.5-bit codec

## Integration contract
1. Resolve each expert's original tensor slice with `GlobalTensorIndex::FindExpertSlice`. Check that offsets are absolute, shard-local file offsets and include the GGUF data-section base exactly once.
2. Register the slice with the bridge. Provide a `Read` callback calling `K2ShardIo_Read`; validate file bounds and quantization block alignment.
3. Provide an `Upload` callback to the **existing, verified** packed decoder and Vulkan upload path. Never reinterpret Q4_K_M bytes as 1.5-bit.
4. Provide an `Execute` callback to the correct Vulkan expert projection kernel. The supplied binding must match the projection and layer.
5. Retain only manifest-approved experts. Mask invalid experts **before router top-k**, not after.
6. Pinball reuses resident device bindings; it does not reconstruct tensors or move them through the CPU.
7. Synchronize GPU work before invalidating bindings; this header does not own GPU allocations.
8. Validate numerical parity and full multi-token inference before enabling on a real model.

## Smoke test
`c++ -std=c++20 -Wall -Wextra -Werror tests/reap_rom_pinball_smoke.cpp -o reap_smoke && ./reap_smoke`

## Outstanding production gates
Actual 1.5-bit decoder integration, quantized tensor layout validation, bounded cache and eviction, async reads, Vulkan fence ownership, REAP manifest verification, MoE router interception, full GGUF shard run, and performance certification.
