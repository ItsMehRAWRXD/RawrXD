// ============================================================================
// codec.h — C++20 Compression/Decompression Interfaceg876
// ============================================================================
#pragma once

#include <vector>
#include <cstdint>

namespace codec {

// Compression info structure
struct CompressionInfo {
    bool valid;
    bool isCompressed;
    uint32_t originalSize;
    uint32_t compressedSize;
    double ratio;
};

// Compress data (auto-detects best method)
std::vector<uint8_t> deflate(const std::vector<uint8_t>& input, bool* success = nullptr);

// Decompress data (auto-detects format)
std::vector<uint8_t> inflate(const std::vector<uint8_t>& input, bool* success = nullptr);

// Get compression info from compressed data
CompressionInfo GetCompressionInfo(const std::vector<uint8_t>& data);

} // namespace codec

// ============================================================================
// C API for MASM/Assembly interop
// ============================================================================

extern "C" {

// Compress data (returns malloc'd buffer, caller must use brutal_free)
void* deflate_brutal_masm(const void* src, size_t len, size_t* out_len);

// Decompress data (returns malloc'd buffer, caller must use brutal_free)
void* inflate_brutal_masm(const void* src, size_t len, size_t* out_len);

// Free memory allocated by deflate/inflate functions
void brutal_free(void* ptr);

// NEON variants (ARM64)
void* deflate_brutal_neon(const void* src, size_t len, size_t* out_len);

} // extern "C"
