# Bounded streaming inflate for compressed tensor pages

## Previous behavior

The compressed pager retained pages in compressed form, but each read inflated an entire page into a temporary raw vector before copying the requested subrange. That made transient host memory scale with page size even for a tiny kernel read.

## New behavior

Compressed page reads now use zlib's streaming `inflate` API with a fixed 32 KiB scratch window. The pager walks the complete compressed stream to validate the page's zlib end marker and exact expanded length, but copies only bytes overlapping the caller's requested subrange. Non-overlapping decoded bytes are discarded immediately.

- No full-page raw scratch allocation for compressed cache hits.
- Requested bytes are copied directly into the caller's output range.
- Full-page stream validation is retained, including exact output length and no trailing compressed input.
- Raw-fallback pages continue to copy only the requested interval.
- The encoded-page cache remains bounded by its configured resident budget.

This bounds transient decompression scratch to 32 KiB per active read, in addition to the caller-owned destination and encoded page cache. Page-cache lookup/LRU mutation is protected by a short mutex. Source reads and compression run outside that cache lock, and returned immutable pages use shared leases so eviction cannot invalidate in-flight readers. Streaming inflate also runs outside the cache lock. The current TensorROM file reader still serializes access to its shared file stream, but CPU decompression and cached-page copies can proceed concurrently.

## Regression

`test_compressed_tensor_pager` covers:
- partial reads from a highly compressible page;
- cross-page reads across compressed and raw-fallback pages;
- byte-for-byte correctness;
- cache hits without additional source reads;
- encoded residency budget accounting;
- out-of-range and zero-length reads.

Build and run:

```sh
cmake -S . -B build
cmake --build build --target test_compressed_tensor_pager
ctest --test-dir build -R compressed_tensor_pager --output-on-failure
``

The connector environment did not execute the native build or CTest. Verify with the Windows/MSVC build before promotion.
