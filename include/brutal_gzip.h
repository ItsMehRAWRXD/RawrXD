#pragma once
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// RFC 1952 gzip containing RFC 1951 DEFLATE stored blocks - x64 MASM.
// Throughput-oriented framing/copy: it does not attempt LZ/Huffman compression.
// Returns a malloc-ed buffer that must be freed with free() by the caller.
// A null src is accepted only when len == 0. A valid empty gzip member is
// still returned. out_len is initialized to zero on failure.
void* deflate_brutal_masm(const void* src, size_t len, size_t* out_len);

// Brutal deflate (stored blocks only) - ARM64 NEON
// Returns a malloc-ed buffer that must be freed by the caller.
// out_len is set to the size of the compressed data.
void* deflate_brutal_neon(const void* src, size_t len, size_t* out_len);

#ifdef __cplusplus
}
#endif
