#pragma once
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Fast gzip framing with DEFLATE stored blocks (BTYPE=00); valid gzip
// packaging, not entropy compression, and may expand the input slightly.
// Returns a malloc-ed gzip buffer that must be freed by the caller.
// out_len is mandatory and is set to the complete gzip stream size.
// A null src is accepted only when len is zero.
void* deflate_brutal_masm(const void* src, size_t len, size_t* out_len);

// ARM64 implementation with the same valid gzip/stored-block contract.
void* deflate_brutal_neon(const void* src, size_t len, size_t* out_len);

// Portable C++ stored-block gzip fallback with the same RFC 1952 contract.
void* gzip_masm_alloc(const void* src, size_t len, size_t* out_len);

#ifdef __cplusplus
}
#endif
