# MASM stored-block gzip path

The x64 MASM routine is a fast RFC 1951 **stored-block encoder**. It copies input into DEFLATE blocks of at most 65,535 bytes; it does not search for matches or entropy-code the input. Consequently it is useful as a low-latency gzip wrapper for already-compressed or incompressible payloads, but it is not a general-purpose size-reduction codec. Random input grows by 18 bytes for the gzip header/trailer plus 5 bytes per stored block.

The raw MASM routine reserves a gzip trailer and leaves the CRC32 field zero. Calling that symbol directly does **not** produce a valid gzip member. Product/test callers must use `deflate_brutal_masm` from `src/codec/brutal_gzip_masm_adapter.cpp`, which:

- validates arguments and length arithmetic;
- handles zero-length input with a valid final empty stored block;
- invokes the raw assembly routine for non-empty input;
- computes the RFC 1952 CRC32 and writes CRC32 and ISIZE little-endian;
- returns a malloc-owned buffer compatible with `free`.

The CTest regression uses zlib's independent gzip decoder (`inflateInit2(MAX_WBITS + 16)`) on empty, tiny, 65,535-byte, 65,536-byte, and 1 MiB deterministic inputs. It validates the gzip trailer and exact byte-for-byte payload recovery, not merely allocation or process exit.

The supplied local benchmark report of 1 MiB in 0.23 ms is a user-reported measurement. The updated benchmark measures the checksum-finalized wrapper over ten iterations and reports encoded/input ratio and throughput. Do not compare stored-block throughput directly with Qt/zlib level-9 compression latency as if the two produced equivalent compression ratios.

## zlib provider build gate

The root build's `rawrxd_compression_core` provider detection supports imported `ZLIB::ZLIB`, legacy FindZLIB variables, FetchContent's `zlib` target, and a local source-tree fallback. The local fallback is accepted only when both `zlib.h` and generated `zconf.h` are present; it compiles the local C sources and publishes `RAWRXD_HAVE_ZLIB=1`.

`compression_zlib_provider_compile_test` includes the public zlib header and roundtrips through the product core's public dependency closure. The Windows workflow also compiles this provider smoke directly against vcpkg zlib. This verifies compilation/linkage and codec operation with a discovered provider; it does not prove the no-provider fallback or every local-tree layout.
