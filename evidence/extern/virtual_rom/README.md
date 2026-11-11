# RawrXD sparse virtual ROM source drop

C++17, standard library only. `VirtualROM` exposes a large logical byte range while keeping at most `floor(budget/page_size)` cache pages resident. The `Reader` callback is the exact-data provider: map it to GGUF file offsets, memory-mapped model shards, or a verified reversible reconstruction routine. **It cannot recover information that does not exist in the backing source.**

Build smoke test: `g++ -std=c++17 -O2 -Wall -Wextra -pedantic test.cpp -o test && ./test`.

Integration: construct with logical byte size, 4096/65536-byte page size, RAM budget, and a callback that reads exact bytes from the underlying ROM/model; use `read` for byte ranges; call `invalidate` when backing data changes. For GPU inference, upload returned bytes using your existing G02 transfer path and honor G04 fences/pins; this module alone does **not** implement Vulkan, GPU residency, concurrent pinning, durable disk paging, or GGUF decoding.

Limitations: cache is non-thread-safe; caller must serialize reads/invalidation. A failed backing read throws without evicting a page. The callback should not recursively invoke the same VirtualROM. The budget counts payload page bytes, not map/list metadata. Cache replacement is LRU; not optimized for sequential prefetch. The demo's deterministic byte generator is a test backing source, **not** a model-weight reconstruction algorithm.
