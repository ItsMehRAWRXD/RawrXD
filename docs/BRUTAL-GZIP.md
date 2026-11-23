# Brutal Gzip: Stored-Block Encoder

## Format and behavior

The x64 MASM routine emits a standard RFC 1952 gzip member containing RFC 1951
DEFLATE stored blocks. It is deliberately a throughput-oriented framing/copy
path, not a dictionary or entropy compressor.

- Each non-empty block contains at most 65,535 payload bytes.
- Each stored block adds five bytes (block header, LEN and NLEN).
- The gzip header and trailer add 18 bytes.
- The output size is therefore input size + 5 bytes per block + 18 bytes.
- Incompressible input is expected to expand slightly; repetitive input is
  also stored verbatim by this specific kernel.
- The trailer contains IEEE CRC-32/ISO-HDLC and the original size modulo 2^32.
- Empty input is represented by one final empty DEFLATE stored block.

The MASM implementation now writes a standards-compliant gzip header (FLG=0,
no absent FNAME field), calculates CRC-32 with the IEEE polynomial, handles
empty input, rejects a null source for non-empty input, and initializes the
output length to zero on failure.

## Interoperability test

On MSVC x64 with zlib available, CMake registers
`brutal_masm_gzip_contract_test`. It validates empty input, a 1 MiB repeated
payload, deterministic 1 MiB high-entropy input, header fields, exact stored
block framing, and a complete gzip decode through zlib. The zlib decoder checks
the gzip trailer CRC and ISIZE as part of the roundtrip.

## Performance notes

A local benchmark result reported for the pre-correction stored-block path was
1 MiB of random input in 0.23 ms, producing 1,048,679 bytes (exit code 0).
That measurement establishes a throughput datapoint only. It does not establish
compression ratio or post-CRC-fix latency; rerun the benchmark and the
interoperability CTest after rebuilding the corrected assembly.

## Model-weight compression

This kernel is not the codec used to obtain high compression ratios for model
weights. RawrXD's block-resident tensor codec uses independently decodable
blocks, checksums, and a bounded decoded-block cache. The inference objective
is to retain those encoded blocks in memory and decode only the byte ranges
required by an operator. The MASM stored-block path may be useful for fast
framing or transport, but it must not be described as shrinking random or
repetitive tensor payloads.

## Runtime decoder contract

The dependency-free C++ wrapper now validates the full stored-block gzip
contract before returning bytes: every LEN/NLEN pair, the optional header CRC16,
the IEEE CRC32 trailer, and ISIZE are checked. It rejects trailing bytes and
supports an explicit decompressed-output ceiling (16 GiB default). The maximum
output-size planner uses checked arithmetic and accounts for the mandatory
empty stored block. The CMake test covers both zlib interoperability and
wrapper-level corruption/ceiling rejection.
