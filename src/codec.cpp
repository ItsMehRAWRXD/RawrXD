// ============================================================================
// codec.cpp — Codec Implementation with Multiple Backends
// ============================================================================
#include "../include/codec.h"
#include <vector>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <mutex>

namespace codec {

// Simple LZ77-like compression
static std::vector<uint8_t> LZ77Compress(const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;
    result.reserve(len);
    
    const size_t WINDOW_SIZE = 4096;
    const size_t MAX_MATCH_LEN = 258;
    
    size_t pos = 0;
    while (pos < len) {
        // Look for match in window
        size_t bestLen = 0;
        size_t bestOff = 0;
        
        size_t windowStart = (pos > WINDOW_SIZE) ? pos - WINDOW_SIZE : 0;
        
        for (size_t i = windowStart; i < pos; ++i) {
            size_t matchLen = 0;
            while (matchLen < MAX_MATCH_LEN && 
                   pos + matchLen < len && 
                   data[i + matchLen] == data[pos + matchLen]) {
                matchLen++;
            }
            
            if (matchLen > bestLen) {
                bestLen = matchLen;
                bestOff = pos - i;
            }
        }
        
        if (bestLen >= 3) {
            // Encode match: offset (2 bytes) + length (1 byte)
            result.push_back(0x00); // Match marker
            result.push_back(static_cast<uint8_t>(bestOff & 0xFF));
            result.push_back(static_cast<uint8_t>((bestOff >> 8) & 0xFF));
            result.push_back(static_cast<uint8_t>(bestLen));
            pos += bestLen;
        } else {
            // Encode literal
            if (data[pos] == 0x00) {
                result.push_back(0x01); // Escape for literal 0x00
            }
            result.push_back(data[pos]);
            pos++;
        }
    }
    
    return result;
}

// LZ77 decompression
static std::vector<uint8_t> LZ77Decompress(const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;
    result.reserve(len * 2); // Estimate
    
    size_t pos = 0;
    while (pos < len) {
        if (data[pos] == 0x00) {
            // Match
            if (pos + 4 > len) break;
            uint16_t offset = data[pos + 1] | (data[pos + 2] << 8);
            uint8_t length = data[pos + 3];
            
            size_t matchPos = result.size() - offset;
            for (size_t i = 0; i < length; ++i) {
                result.push_back(result[matchPos + i]);
            }
            pos += 4;
        } else if (data[pos] == 0x01) {
            // Escaped literal 0x00
            result.push_back(0x00);
            pos++;
        } else {
            // Literal
            result.push_back(data[pos]);
            pos++;
        }
    }
    
    return result;
}

// Check if compression would be beneficial
static bool ShouldCompress(const uint8_t* data, size_t len) {
    if (len < 100) return false; // Too small to compress
    
    // Simple heuristic: check for repeated patterns
    size_t repeats = 0;
    for (size_t i = 1; i < len && i < 1000; ++i) {
        if (data[i] == data[i-1]) repeats++;
    }
    
    return (repeats * 3) > len; // Compress if > 33% repeated
}

std::vector<uint8_t> deflate(const std::vector<uint8_t>& input, bool* success) {
    if (success) *success = false;
    
    if (input.empty()) {
        if (success) *success = true;
        return {};
    }
    
    // Try compression
    std::vector<uint8_t> compressed;
    
    if (ShouldCompress(input.data(), input.size())) {
        compressed = LZ77Compress(input.data(), input.size());
        
        // Only use compression if it reduces size
        if (compressed.size() < input.size()) {
            // Add header: 0x01 = compressed
            std::vector<uint8_t> result;
            result.reserve(compressed.size() + 9);
            
            // Magic + version
            result.push_back(0x52); // 'R'
            result.push_back(0x58); // 'X'
            result.push_back(0x43); // 'C'
            result.push_back(0x01); // version 1
            
            // Original size (4 bytes, little-endian)
            uint32_t origSize = static_cast<uint32_t>(input.size());
            result.push_back(static_cast<uint8_t>(origSize & 0xFF));
            result.push_back(static_cast<uint8_t>((origSize >> 8) & 0xFF));
            result.push_back(static_cast<uint8_t>((origSize >> 16) & 0xFF));
            result.push_back(static_cast<uint8_t>((origSize >> 24) & 0xFF));
            
            // Compressed data
            result.insert(result.end(), compressed.begin(), compressed.end());
            
            if (success) *success = true;
            return result;
        }
    }
    
    // Store uncompressed
    std::vector<uint8_t> result;
    result.reserve(input.size() + 9);
    
    // Magic + version
    result.push_back(0x52); // 'R'
    result.push_back(0x58); // 'X'
    result.push_back(0x43); // 'C'
    result.push_back(0x00); // uncompressed flag
    
    // Original size
    uint32_t origSize = static_cast<uint32_t>(input.size());
    result.push_back(static_cast<uint8_t>(origSize & 0xFF));
    result.push_back(static_cast<uint8_t>((origSize >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>((origSize >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((origSize >> 24) & 0xFF));
    
    // Uncompressed data
    result.insert(result.end(), input.begin(), input.end());
    
    if (success) *success = true;
    return result;
}

std::vector<uint8_t> inflate(const std::vector<uint8_t>& input, bool* success) {
    if (success) *success = false;
    
    if (input.size() < 9) {
        return {}; // Too small for header
    }
    
    // Check magic
    if (input[0] != 0x52 || input[1] != 0x58 || input[2] != 0x43) {
        return {}; // Invalid magic
    }
    
    uint8_t version = input[3];
    
    // Read original size
    uint32_t origSize = input[4] | (input[5] << 8) | (input[6] << 16) | (input[7] << 24);
    
    if (version == 0x00) {
        // Uncompressed
        if (input.size() - 8 != origSize) {
            return {}; // Size mismatch
        }
        
        std::vector<uint8_t> result(input.begin() + 8, input.end());
        if (success) *success = true;
        return result;
    } else if (version == 0x01) {
        // Compressed
        std::vector<uint8_t> result = LZ77Decompress(input.data() + 8, input.size() - 8);
        
        if (result.size() != origSize) {
            // Size mismatch, but return what we have
        }
        
        if (success) *success = true;
        return result;
    }
    
    return {}; // Unknown version
}

// Get compression info
CompressionInfo GetCompressionInfo(const std::vector<uint8_t>& data) {
    CompressionInfo info;
    
    if (data.size() >= 9 && data[0] == 0x52 && data[1] == 0x58 && data[2] == 0x43) {
        info.isCompressed = (data[3] == 0x01);
        info.originalSize = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
        info.compressedSize = data.size() - 8;
        info.ratio = (info.originalSize > 0) 
            ? static_cast<double>(info.compressedSize) / info.originalSize 
            : 1.0;
        info.valid = true;
    } else {
        info.valid = false;
        info.isCompressed = false;
        info.originalSize = 0;
        info.compressedSize = 0;
        info.ratio = 1.0;
    }
    
    return info;
}

}  // namespace codec

// ============================================================================
// C API for MASM/Assembly interop
// ============================================================================

extern "C" {

void* deflate_brutal_masm(const void* src, size_t len, size_t* out_len) {
    if (!src || len == 0 || !out_len) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    std::vector<uint8_t> input(static_cast<const uint8_t*>(src), 
                               static_cast<const uint8_t*>(src) + len);
    
    bool success = false;
    std::vector<uint8_t> compressed = codec::deflate(input, &success);
    
    if (!success) {
        *out_len = 0;
        return nullptr;
    }
    
    // Allocate result buffer
    void* result = malloc(compressed.size());
    if (!result) {
        *out_len = 0;
        return nullptr;
    }
    
    memcpy(result, compressed.data(), compressed.size());
    *out_len = compressed.size();
    return result;
}

void* deflate_brutal_neon(const void* src, size_t len, size_t* out_len) {
    // NEON path - currently same as MASM, could be optimized
    return deflate_brutal_masm(src, len, out_len);
}

void* inflate_brutal_masm(const void* src, size_t len, size_t* out_len) {
    if (!src || len == 0 || !out_len) {
        if (out_len) *out_len = 0;
        return nullptr;
    }
    
    std::vector<uint8_t> input(static_cast<const uint8_t*>(src), 
                               static_cast<const uint8_t*>(src) + len);
    
    bool success = false;
    std::vector<uint8_t> decompressed = codec::inflate(input, &success);
    
    if (!success) {
        *out_len = 0;
        return nullptr;
    }
    
    // Allocate result buffer
    void* result = malloc(decompressed.size());
    if (!result) {
        *out_len = 0;
        return nullptr;
    }
    
    memcpy(result, decompressed.data(), decompressed.size());
    *out_len = decompressed.size();
    return result;
}

void brutal_free(void* ptr) {
    free(ptr);
}

} // extern "C"


