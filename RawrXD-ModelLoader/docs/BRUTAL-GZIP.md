# Brutal gzip: stored-block framing

The MASM x64 and AArch64 implementations emit a valid RFC 1952 gzip stream
whose DEFLATE payload uses stored blocks (BTYPE=00). This is a fast framing /
copy path, **not a compression algorithm**: output is larger than input by the
gzip header/trailer and five bytes per 65,535-byte stored block.

## Correctness contract

- Gzip header: ID1/ID2, DEFLATE method, no optional fields.
- Stored blocks: valid BFINAL, LEN, and one's-complement NLEN.
- Trailer: IEEE CRC32 (polynomial 0xEDB88320) and ISIZE modulo 2^32.
- Empty input emits a final empty stored block.
- Null source is accepted only when len is zero; out_len is required.
- Allocation-size arithmetic is checked for overflow.
- Both x64 and AArch64 paths use the shared IEEE CRC32 implementation.

## End-to-end validation

`tests/test_deflate_brutal_gzip.cpp` validates exact roundtrips for empty,
single-byte, repetitive, random, 65,535-byte boundary, multi-block, and 1 MiB
payloads. It also flips the gzip CRC trailer and requires corruption rejection.
The validator is independent of the encoder's CRC implementation. The same
test is compiled against MASM on Windows and NEON on AArch64.

The Windows GitHub Actions workflow assembles the MASM object with ML64,
compiles the CRC helper, runs the roundtrip/corruption tests, and only then
runs the benchmark. The benchmark reports packaging latency and expansion
ratio; it does not compare stored-block copying against a compression codec.

## Previous benchmark claims

The earlier 0.21–0.23 ms timings measured construction of an uncompressed
stored-block stream. They did not demonstrate a 200x compression speedup,
and the prior MASM/NEON kernels wrote a zero CRC32 trailer. Those results are
superseded until the new CI roundtrip suite passes.

## Architecture selection

- x64 MSVC: `kernels/deflate_brutal_masm.asm`
- AArch64: `kernels/deflate_brutal_neon.S`
- Shared IEEE CRC32: `src/gzip_crc32.cpp`
