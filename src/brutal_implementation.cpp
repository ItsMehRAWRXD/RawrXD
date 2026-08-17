// ============================================================================
// brutal_implementation.cpp — Brutal Compression Implementation
// ============================================================================
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>
#include <limits>

namespace brutal
{

// Simple RLE compression as fallback
static std::vector<uint8_t> RLECompress(const uint8_t* data, size_t size) {
    std::vector<uint8_t> result;
    result.reserve(size);
    
    size_t i = 0;
    while (i < size) {
        uint8_t current = data[i];
        size_t count = 1;
        
        // Count consecutive identical bytes
        while (i + count < size && data[i + count] == current && count < 255) {
            count++;
        }
        
        // Store count and value
        result.push_back(static_cast<uint8_t>(count));
        result.push_back(current);
        
        i += count;
    }
    
    return result;
}

// Simple RLE decompression
static std::vector<uint8_t> RLEDecompress(const uint8_t* data, size_t size) {
    std::vector<uint8_t> result;
    result.reserve(size * 2); // Estimate
    
    size_t i = 0;
    while (i + 1 < size) {
        uint8_t count = data[i];
        uint8_t value = data[i + 1];
        
        result.insert(result.end(), count, value);
        i += 2;
    }
    
    return result;
}

// Check if RLE would be beneficial
static bool ShouldUseRLE(const uint8_t* data, size_t size) {
    if (size < 4) return false;
    
    size_t runCount = 0;
    for (size_t i = 1; i < size; ++i) {
        if (data[i] == data[i-1]) {
            runCount++;
        }
    }
    
    // Use RLE if more than 25% of bytes are in runs
    return (runCount * 4) > size;
}

// Compress with auto-detection of best method
std::vector<uint8_t> compress(const std::vector<uint8_t>& in)
{
    if (in.empty()) {
        return {};
    }
    
    // Check if RLE would be beneficial
    if (ShouldUseRLE(in.data(), in.size())) {
        auto compressed = RLECompress(in.data(), in.size());
        
        // Only use compression if it actually reduces size
        if (compressed.size() < in.size()) {
            // Add header byte to indicate RLE compression
            compressed.insert(compressed.begin(), 0x01);
            return compressed;
        }
    }
    
    // Store uncompressed with header
    std::vector<uint8_t> result;
    result.reserve(in.size() + 1);
    result.push_back(0x00); // Uncompressed marker
    result.insert(result.end(), in.begin(), in.end());
    return result;
}

std::vector<uint8_t> compress(const void* data, std::size_t size)
{
    if (!data || size == 0) {
        return {};
    }
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    return compress(std::vector<uint8_t>(ptr, ptr + size));
}

std::vector<uint8_t> decompress(const std::vector<uint8_t>& in)
{
    if (in.empty()) {
        return {};
    }
    
    // Check compression type from header
    uint8_t compressionType = in[0];
    
    if (compressionType == 0x01 && in.size() > 1) {
        // RLE compressed
        return RLEDecompress(in.data() + 1, in.size() - 1);
    }
    
    // Uncompressed or unknown type - return data without header
    return std::vector<uint8_t>(in.begin() + 1, in.end());
}

// Get compression statistics
CompressionStats GetCompressionStats(const std::vector<uint8_t>& original,
                                      const std::vector<uint8_t>& compressed) {
    CompressionStats stats;
    stats.originalSize = original.size();
    stats.compressedSize = compressed.size();
    stats.ratio = (original.size() > 0) 
        ? static_cast<double>(compressed.size()) / original.size()
        : 1.0;
    stats.savings = (original.size() > compressed.size()) 
        ? original.size() - compressed.size()
        : 0;
    return stats;
}

}  // namespace brutal
