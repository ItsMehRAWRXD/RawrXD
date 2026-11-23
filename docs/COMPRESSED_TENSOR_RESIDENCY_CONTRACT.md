# Bounded compressed tensor residency contract

This branch adds a codec-neutral block store so the native codec and zlib can
feed inference consumers through one bounded range-read API.

## Guarantees
- Compressed bytes remain the persistent representation; reads expand only
  blocks intersecting the requested logical byte range.
- Each decoded block must have the exact advertised output size and pass CRC-32.
- The decoded cache is byte-bounded. Evicted blocks remain safe for active
  readers through shared ownership.
- Block coverage and source/output ranges are validated with overflow-safe
  bounds checks before use.
- Codec failures are returned as read failures; there is no implicit raw fallback.

## Required integration work
1. Adapt the existing native codec and zlib path to the BlockDecoder callback.
2. Build descriptors from GGUF tensor ranges without rewriting GGUF.
3. Route CPU GEMV and quantized dot-product reads through this range API.
4. Add Vulkan staging that requests only blocks required by the dispatched tile.
5. Preserve Q4/Q5/Q8/K-quant block encodings; do not expand them to F32 merely
   to compress them.
6. Keep each tensor type gated until independent logits parity is measured.

## Standalone contract test
Compile with C++17:
c++ -std=c++17 -Wall -Wextra -Iinclude tests/compressed_block_store_contract_test.cpp -o compressed_block_store_test
./compressed_block_store_test

The identity decoder in the test isolates range, cache, directory, and checksum
semantics. It is not a compression-ratio or production-codec benchmark.
