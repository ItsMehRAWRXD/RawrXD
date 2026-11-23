# Compressed block codec adapters

This change gives the codec-neutral `CompressedBlockStore` concrete adapters for both the native RawrXD block codec and the existing zlib core.

## Wire and residency contract

- Encoded bytes remain the persistent representation.
- Each tensor is split into independent blocks; the directory maps logical byte ranges to the concatenated encoded stream.
- Each directory entry carries an exact raw byte count and CRC-32 of the decoded bytes.
- A block is stored raw when compression is not strictly smaller. The paired adapter recognizes raw fallback by `compressed_size == raw_size`.
- The decoded LRU cache is bounded by decoded bytes. Active readers retain shared leases after eviction.
- Block decompression and CRC verification occur outside the cache mutex. Only cache lookup, LRU mutation, insertion, and eviction are serialized.
- Codec failure, short output, bad checksums, malformed directories, and out-of-range reads fail closed.

## Native codec compatibility

`native_lz_block_codec.hpp` extracts the existing Deep2 `CompressedWeightStore` token format: a control byte followed by up to eight literals or three-byte back-references (distance-1:u16, length:u8). `CompressedWeightStore.cpp` now delegates encoding/decoding to this shared implementation, preserving its existing raw fallback and CRC checks. The regression executable exercises both the new generic store and the production Deep2 store with the same tensor bytes.

## zlib auto-detection and optional builds

`zlibBlockEncoder` and `zlibBlockDecoder` use the existing Qt-independent `rawrxd_compression_core` API. The adapter is available only when the CMake configuration found or fetched a zlib provider; otherwise the core reports `Status::Unsupported` and zlib store creation fails rather than silently storing uncompressed data while claiming zlib support. Native LZ remains available without zlib.

## Tests

The CTest target `compressed_block_codec_adapters_test` verifies:
- native LZ compression and partial range reads;
- decoded cache byte budget;
- concurrent readers over shared and distinct blocks;
- zlib roundtrip when the provider is available;
- explicit unsupported behavior when zlib is absent;
- production `CompressedWeightStore` compatibility after codec extraction;
- raw fallback for incompressible input.

A GitHub Actions workflow compiles and runs the test in both zlib-enabled and native-only configurations. Windows/MSVC full-project build and Vulkan integration remain separate acceptance gates.
