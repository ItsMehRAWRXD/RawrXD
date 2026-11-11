# DEEP2_TIERED_MOE_001 — bounded host tensor cache (source drop)

Native C++20, standard library only. Does not modify GGUF files or download anything.

## Build
Windows (Visual Studio generator):
```
cmake -S . -B build -A x64 -DBUILD_TESTING=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```
Linux portability smoke test:
```
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Deep2 integration
Copy include/deep2_tiered_moe.hpp and src/deep2_tiered_moe.cpp into Deep2 and register a library target, or add_subdirectory this folder.
Construct Tensor descriptors from Deep2's **existing validated GGUF loader**, using absolute shard paths and checked tensor offsets. Never derive tensor byte ranges from guessed quantization block sizes. Build the cache with a measured host budget, then acquire a Lease before any tensor upload. Keep the lease alive until the GPU transfer completes (fence/queue completion). The Lease protects host data only; GPU buffers and fences remain the Vulkan backend's responsibility.

## What is implemented
- Bounds-checked tensor descriptors and indexed lookup
- Exact file reads, including truncated-file rejection
- Capacity-bounded, pinned-lease LRU host cache
- Explicit eviction failure when all candidates are pinned
- Hit/miss/read/eviction and resident/pinned-byte telemetry
- Conservative host admission calculator
- Unit test for pinning, eviction, reads, admission and invalid ranges

## NOT implemented / not certified
- GGUF binary parser (integrate existing Deep2 parser)
- Asynchronous I/O, background prefetch, GPU staging, GPU memory allocation, Vulkan dispatch or GPU fences
- Expert routing/prediction, multi-GPU scheduling, compressed representations, BF16 reconstruction
- Multi-process file consistency, in-place file modification detection, cancellation, runtime shutdown with outstanding leases
- Real-model logits parity, 65/103/377 GiB model generation, TPS or 1M context

Important: Cache object must outlive all Leases. File identity is path+offset+size; do not modify model shards during use. Cache serializes disk misses for deterministic capacity management. It is intentionally a safe baseline, not the final high-throughput streaming implementation.
