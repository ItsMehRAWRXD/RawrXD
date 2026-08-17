// ============================================================================
// brutal/compression.h — Brutal Compression Interface
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace brutal
{

// Compression statistics
struct CompressionStats {
    size_t originalSize;
    size_t compressedSize;
    double ratio;
    size_t savings;
};

// Compress data with auto-detection of best method
std::vector<uint8_t> compress(const std::vector<uint8_t>& in);

// Compress from raw pointer
std::vector<uint8_t> compress(const void* data, std::size_t size);

// Decompress data (auto-detects compression type)
std::vector<uint8_t> decompress(const std::vector<uint8_t>& in);

// Get compression statistics
CompressionStats GetCompressionStats(const std::vector<uint8_t>& original,
                                      const std::vector<uint8_t>& compressed);

}  // namespace brutal
