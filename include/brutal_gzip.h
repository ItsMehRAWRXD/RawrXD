#pragma once
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// x64 MASM stored-block gzip encoder with C++ CRC32/ISIZE finalization.
// The returned bytes are a standards-valid RFC 1952 gzip member. Stored
// DEFLATE blocks favor low latency, not entropy compression; incompressible
// inputs grow by the gzip header/trailer and per-block LEN/NLEN overhead.
// Returns a malloc-ed buffer that must be freed by the caller.
// out_len is set to the complete gzip member size.
void* deflate_brutal_masm(const void* src, size_t len, size_t* out_len);

// Brutal deflate (stored blocks only) - ARM64 NEON
// Returns a malloc-ed buffer that must be freed by the caller.
// out_len is set to the size of the compressed data.
void* deflate_brutal_neon(const void* src, size_t len, size_t* out_len);

#ifdef __cplusplus
}
#endif
